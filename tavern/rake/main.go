package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/jessevdk/go-flags"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"realm.pub/tavern/internal/c2"
	"realm.pub/tavern/internal/c2/c2pb"
	"realm.pub/tavern/internal/c2/epb"
	"realm.pub/tavern/internal/cryptocodec"
	"realm.pub/tavern/internal/ent"
	"realm.pub/tavern/internal/ent/host"
	"realm.pub/tavern/internal/ent/migrate"
	_ "realm.pub/tavern/internal/ent/runtime"
	"realm.pub/tavern/internal/ent/tome"
	"realm.pub/tavern/tomes"
)

type Options struct {
	DBName     string `short:"d" long:"db-name" description:"Path to the SQLite database file" required:"true"`
	TomesPath  string `short:"t" long:"tomes-path" description:"Path to the Tomes directory" required:"true"`
	ListenAddr string `short:"l" long:"listen" description:"Address to listen on (e.g. :8000)" default:":8000"`
	PrivateKey string `short:"k" long:"private-key" description:"Base64 encoded X25519 private key. If not provided, a random one is generated."`
}

// RakeServer wraps c2.Server to add extended functionality
type RakeServer struct {
	*c2.Server
	client *ent.Client
}

// CredentialExport is the JSON structure for exported credentials
type CredentialExport struct {
	Principal string `json:"principal"`
	Secret    string `json:"secret"`
	Kind      string `json:"kind"`
}

func (s *RakeServer) FetchAsset(req *c2pb.FetchAssetRequest, stream c2pb.C2_FetchAssetServer) error {
	if strings.HasPrefix(req.Name, "host:credentials") {
		ctx := stream.Context()
		
		var hostIdentifier string
		if strings.HasPrefix(req.Name, "host:credentials:") {
			hostIdentifier = strings.TrimPrefix(req.Name, "host:credentials:")
		}
		
		if hostIdentifier == "" {
			return status.Errorf(codes.InvalidArgument, "must specify host identifier in asset name, e.g. host:credentials:<id>")
		}

		h, err := s.client.Host.Query().
			Where(host.IdentifierEQ(hostIdentifier)).
			Only(ctx)
		if ent.IsNotFound(err) {
			return status.Errorf(codes.NotFound, "host not found")
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to query host: %v", err)
		}

		creds, err := h.QueryCredentials().All(ctx)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to query credentials: %v", err)
		}

		var export []CredentialExport
		for _, c := range creds {
			kind := "UNKNOWN"
			switch c.Kind {
			case epb.Credential_KIND_PASSWORD:
				kind = "PASSWORD"
			case epb.Credential_KIND_SSH_KEY:
				kind = "SSH_KEY"
			}
			export = append(export, CredentialExport{
				Principal: c.Principal,
				Secret:    c.Secret,
				Kind:      kind,
			})
		}

		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return status.Errorf(codes.Internal, "failed to marshal credentials: %v", err)
		}

		stream.SetHeader(metadata.Pairs(
			"file-size", fmt.Sprintf("%d", len(data)),
		))

		return stream.Send(&c2pb.FetchAssetResponse{
			Chunk: data,
		})
	}

	return s.Server.FetchAsset(req, stream)
}

func getRemoteIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return "unknown"
	}
	return host
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// 1. Setup SQLite Connection
	drv, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=rwc&cache=shared&_fk=1", opts.DBName))
	if err != nil {
		log.Fatalf("failed to open sqlite database: %v", err)
	}
	defer drv.Close()

	client := ent.NewClient(ent.Driver(drv))
	defer client.Close()

	ctx := context.Background()

	// 2. Create Schema (Migrations)
	if err := client.Schema.Create(
		ctx,
		migrate.WithGlobalUniqueID(true),
	); err != nil {
		log.Fatalf("failed to initialize graph schema: %v", err)
	}
	log.Printf("Database initialized at %s", opts.DBName)

	// 3. Load Tomes
	log.Printf("Loading tomes from %s", opts.TomesPath)
	tomesFS := os.DirFS(opts.TomesPath)

	if readDirFS, ok := tomesFS.(fs.ReadDirFS); ok {
		if err := tomes.UploadTomes(ctx, client, readDirFS); err != nil {
			log.Fatalf("failed to upload tomes: %v", err)
		}
	} else {
		log.Fatalf("os.DirFS result does not implement fs.ReadDirFS")
	}

	// 3a. Mark Tomes as Autorun
	_, err = client.Tome.Update().
		Where(tome.RunOnNewBeaconCallback(false)).
		SetRunOnNewBeaconCallback(true).
		Save(ctx)
	if err != nil {
		log.Printf("failed to mark tomes as autorun: %v", err)
	} else {
		log.Println("Marked all tomes as autorun (RunOnNewBeaconCallback).")
	}

	log.Println("Tomes loaded successfully.")

	// 4. Setup Key Pair
	var privKey *ecdh.PrivateKey
	var pubKey *ecdh.PublicKey
	curve := ecdh.X25519()

	if opts.PrivateKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
		if err != nil {
			log.Fatalf("failed to decode private key: %v", err)
		}
		privKey, err = curve.NewPrivateKey(keyBytes)
		if err != nil {
			log.Fatalf("invalid private key: %v", err)
		}
	} else {
		log.Println("No private key provided, generating a random one...")
		var err error
		privKey, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate private key: %v", err)
		}
	}
	
	pubKey = privKey.PublicKey()
	log.Printf("Server Public Key (Base64): %s", base64.StdEncoding.EncodeToString(pubKey.Bytes()))

	// 5. Setup gRPC Server
	// We use our custom RakeServer
	baseC2 := c2.New(client, nil, nil)
	rakeSrv := &RakeServer{
		Server: baseC2,
		client: client,
	}

	xchacha := cryptocodec.StreamDecryptCodec{
		Csvc: cryptocodec.NewCryptoSvc(privKey),
	}

	grpcSrv := grpc.NewServer(
		grpc.ForceServerCodecV2(xchacha),
	)

	c2pb.RegisterC2Server(grpcSrv, rakeSrv)

	// 6. Wrap in HTTP/2 (h2c) handler
	handler := h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "grpc requires HTTP/2", http.StatusBadRequest)
			return
		}
		if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/grpc") {
			http.Error(w, "must specify Content-Type application/grpc", http.StatusBadRequest)
			return
		}
		grpcSrv.ServeHTTP(w, r)
	}), &http2.Server{})

	// 7. Start Server
	log.Printf("Listening on %s", opts.ListenAddr)
	if err := http.ListenAndServe(opts.ListenAddr, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
