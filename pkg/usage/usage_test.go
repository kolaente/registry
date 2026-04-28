package usage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeFilesystemAttributesSharedBlobsAcrossRepositories(t *testing.T) {
	root := t.TempDir()

	sharedLayer := writeBlob(t, root, "1111111111111111111111111111111111111111111111111111111111111111", sizedBytes(90))
	appLayer := writeBlob(t, root, "2222222222222222222222222222222222222222222222222222222222222222", sizedBytes(30))
	workerLayer := writeBlob(t, root, "3333333333333333333333333333333333333333333333333333333333333333", sizedBytes(60))
	appConfig := writeBlob(t, root, "4444444444444444444444444444444444444444444444444444444444444444", sizedBytes(10))
	workerConfig := writeBlob(t, root, "5555555555555555555555555555555555555555555555555555555555555555", sizedBytes(20))

	appManifestSize := writeManifest(t, root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", appConfig, []blobRef{sharedLayer, appLayer})
	workerManifestSize := writeManifest(t, root, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", workerConfig, []blobRef{sharedLayer, workerLayer})

	linkTag(t, root, "team/app", "latest", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	linkTag(t, root, "team/worker", "latest", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	report, err := AnalyzeFilesystem(root)
	if err != nil {
		t.Fatalf("AnalyzeFilesystem() error = %v", err)
	}

	if report.TotalReferencedBytes != int64(90+30+60+10+20+appManifestSize+workerManifestSize) {
		t.Fatalf("TotalReferencedBytes = %d, want %d", report.TotalReferencedBytes, 90+30+60+10+20+appManifestSize+workerManifestSize)
	}

	app := findRepository(t, report, "team/app")
	if app.ReferencedBytes != int64(90+30+10+appManifestSize) {
		t.Errorf("app ReferencedBytes = %d, want %d", app.ReferencedBytes, 90+30+10+appManifestSize)
	}
	if app.ExclusiveBytes != int64(30+10+appManifestSize) {
		t.Errorf("app ExclusiveBytes = %d, want %d", app.ExclusiveBytes, 30+10+appManifestSize)
	}
	if app.SharedBytes != 90 {
		t.Errorf("app SharedBytes = %d, want 90", app.SharedBytes)
	}
	if app.AttributedBytes != float64(30+10+appManifestSize)+45 {
		t.Errorf("app AttributedBytes = %.1f, want %.1f", app.AttributedBytes, float64(30+10+appManifestSize)+45)
	}

	worker := findRepository(t, report, "team/worker")
	if worker.ExclusiveBytes != int64(60+20+workerManifestSize) {
		t.Errorf("worker ExclusiveBytes = %d, want %d", worker.ExclusiveBytes, 60+20+workerManifestSize)
	}
	if worker.AttributedBytes != float64(60+20+workerManifestSize)+45 {
		t.Errorf("worker AttributedBytes = %.1f, want %.1f", worker.AttributedBytes, float64(60+20+workerManifestSize)+45)
	}
}

func TestAnalyzeFilesystemReportsUntaggedBlobBytes(t *testing.T) {
	root := t.TempDir()

	layer := writeBlob(t, root, "1111111111111111111111111111111111111111111111111111111111111111", sizedBytes(90))
	config := writeBlob(t, root, "2222222222222222222222222222222222222222222222222222222222222222", sizedBytes(10))
	manifestSize := writeManifest(t, root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", config, []blobRef{layer})
	linkTag(t, root, "team/app", "latest", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	writeBlob(t, root, "3333333333333333333333333333333333333333333333333333333333333333", sizedBytes(70))

	report, err := AnalyzeFilesystem(root)
	if err != nil {
		t.Fatalf("AnalyzeFilesystem() error = %v", err)
	}

	if report.TotalBlobBytes != int64(90+10+manifestSize+70) {
		t.Errorf("TotalBlobBytes = %d, want %d", report.TotalBlobBytes, 90+10+manifestSize+70)
	}
	if report.UnreferencedBytes != 70 {
		t.Errorf("UnreferencedBytes = %d, want 70", report.UnreferencedBytes)
	}
}

func TestAnalyzeFilesystemReturnsEmptyReportForEmptyRegistry(t *testing.T) {
	report, err := AnalyzeFilesystem(t.TempDir())
	if err != nil {
		t.Fatalf("AnalyzeFilesystem() error = %v", err)
	}

	if len(report.Repositories) != 0 {
		t.Fatalf("Repositories length = %d, want 0", len(report.Repositories))
	}
}

func TestFormatBytes(t *testing.T) {
	tests := map[float64]string{
		512:               "512 B",
		1536:              "1.50 KiB",
		10 * 1024:         "10.0 KiB",
		128 * 1024:        "128 KiB",
		8.5 * 1024 * 1024: "8.50 MiB",
	}

	for bytes, want := range tests {
		if got := FormatBytes(bytes); got != want {
			t.Errorf("FormatBytes(%v) = %q, want %q", bytes, got, want)
		}
	}
}

type blobRef struct {
	digest string
	size   int64
}

func writeBlob(t *testing.T, root, digest string, data []byte) blobRef {
	t.Helper()

	path := filepath.Join(root, "docker", "registry", "v2", "blobs", "sha256", digest[:2], digest, "data")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create blob directory: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write blob: %v", err)
	}

	return blobRef{digest: "sha256:" + digest, size: int64(len(data))}
}

func writeManifest(t *testing.T, root, digest string, config blobRef, layers []blobRef) int {
	t.Helper()

	manifest := struct {
		SchemaVersion int            `json:"schemaVersion"`
		Config        manifestBlob   `json:"config"`
		Layers        []manifestBlob `json:"layers"`
	}{
		SchemaVersion: 2,
		Config: manifestBlob{
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      config.size,
			Digest:    config.digest,
		},
		Layers: make([]manifestBlob, 0, len(layers)),
	}

	for _, layer := range layers {
		manifest.Layers = append(manifest.Layers, manifestBlob{
			MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			Size:      layer.size,
			Digest:    layer.digest,
		})
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	writeBlob(t, root, digest, data)
	return len(data)
}

func linkTag(t *testing.T, root, repo, tag, manifestDigest string) {
	t.Helper()

	path := filepath.Join(root, "docker", "registry", "v2", "repositories", filepath.FromSlash(repo), "_manifests", "tags", tag, "current", "link")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create tag directory: %v", err)
	}
	if err := os.WriteFile(path, []byte("sha256:"+manifestDigest), 0644); err != nil {
		t.Fatalf("failed to write tag link: %v", err)
	}
}

func sizedBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = 'x'
	}
	return data
}

func findRepository(t *testing.T, report *Report, name string) RepositoryUsage {
	t.Helper()

	for _, repo := range report.Repositories {
		if repo.Repository == name {
			return repo
		}
	}

	t.Fatalf("repository %q not found", name)
	return RepositoryUsage{}
}
