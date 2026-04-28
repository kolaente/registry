package usage

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Report contains storage usage attributed across tagged repositories.
type Report struct {
	Repositories         []RepositoryUsage `json:"repositories"`
	TotalBlobBytes       int64             `json:"total_blob_bytes"`
	TotalBlobSize        string            `json:"total_blob_size"`
	TotalReferencedBytes int64             `json:"total_referenced_bytes"`
	TotalReferencedSize  string            `json:"total_referenced_size"`
	UnreferencedBytes    int64             `json:"unreferenced_bytes"`
	UnreferencedSize     string            `json:"unreferenced_size"`
}

// RepositoryUsage reports how much registry storage a repository accounts for.
type RepositoryUsage struct {
	Repository      string   `json:"repository"`
	Tags            []string `json:"tags"`
	BlobCount       int      `json:"blob_count"`
	ExclusiveBlobs  int      `json:"exclusive_blobs"`
	SharedBlobs     int      `json:"shared_blobs"`
	ReferencedBytes int64    `json:"referenced_bytes"`
	ReferencedSize  string   `json:"referenced_size"`
	ExclusiveBytes  int64    `json:"exclusive_bytes"`
	ExclusiveSize   string   `json:"exclusive_size"`
	SharedBytes     int64    `json:"shared_bytes"`
	SharedSize      string   `json:"shared_size"`
	AttributedBytes float64  `json:"attributed_bytes"`
	AttributedSize  string   `json:"attributed_size"`
}

type manifestBlob struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type manifestDocument struct {
	SchemaVersion int            `json:"schemaVersion"`
	Config        manifestBlob   `json:"config"`
	Layers        []manifestBlob `json:"layers"`
	Manifests     []manifestBlob `json:"manifests"`
}

// AnalyzeFilesystem returns a usage report for a Docker Distribution filesystem root.
func AnalyzeFilesystem(rootDirectory string) (*Report, error) {
	v2Root := filepath.Join(rootDirectory, "docker", "registry", "v2")
	blobSizes, err := scanBlobSizes(filepath.Join(v2Root, "blobs", "sha256"))
	if err != nil {
		return nil, err
	}

	repoBlobs, repoTags, err := scanTaggedRepositories(v2Root, blobSizes)
	if err != nil {
		return nil, err
	}

	return buildReport(blobSizes, repoBlobs, repoTags), nil
}

// FormatBytes renders byte counts for humans using binary units.
func FormatBytes(bytes float64) string {
	if bytes < 0 {
		return "-" + FormatBytes(-bytes)
	}
	if bytes < 1024 {
		return fmt.Sprintf("%.0f B", bytes)
	}

	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	value := bytes
	unit := "B"
	for _, next := range units {
		value /= 1024
		unit = next
		if value < 1024 {
			break
		}
	}

	if value >= 100 {
		return fmt.Sprintf("%.0f %s", value, unit)
	}
	if value >= 10 {
		return fmt.Sprintf("%.1f %s", value, unit)
	}
	return fmt.Sprintf("%.2f %s", value, unit)
}

func scanBlobSizes(blobsRoot string) (map[string]int64, error) {
	blobSizes := map[string]int64{}

	if _, err := os.Stat(blobsRoot); os.IsNotExist(err) {
		return blobSizes, nil
	}

	err := filepath.WalkDir(blobsRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "data" {
			return nil
		}

		digest := filepath.Base(filepath.Dir(path))
		info, err := entry.Info()
		if err != nil {
			return err
		}
		blobSizes["sha256:"+digest] = info.Size()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan blobs: %w", err)
	}

	return blobSizes, nil
}

func scanTaggedRepositories(v2Root string, blobSizes map[string]int64) (map[string]map[string]struct{}, map[string]map[string]struct{}, error) {
	repositoriesRoot := filepath.Join(v2Root, "repositories")
	repoBlobs := map[string]map[string]struct{}{}
	repoTags := map[string]map[string]struct{}{}

	if _, err := os.Stat(repositoriesRoot); os.IsNotExist(err) {
		return repoBlobs, repoTags, nil
	}

	err := filepath.WalkDir(repositoriesRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "link" {
			return nil
		}

		rel, err := filepath.Rel(repositoriesRoot, path)
		if err != nil {
			return err
		}

		repository, tag, ok := parseTagLinkPath(rel)
		if !ok {
			return nil
		}

		digest, err := readDigestLink(path)
		if err != nil {
			return err
		}

		blobs := map[string]struct{}{}
		if err := collectManifestReferences(v2Root, digest, blobSizes, blobs, map[string]struct{}{}); err != nil {
			return fmt.Errorf("failed to read %s:%s: %w", repository, tag, err)
		}

		if repoBlobs[repository] == nil {
			repoBlobs[repository] = map[string]struct{}{}
		}
		if repoTags[repository] == nil {
			repoTags[repository] = map[string]struct{}{}
		}
		repoTags[repository][tag] = struct{}{}
		for blob := range blobs {
			repoBlobs[repository][blob] = struct{}{}
		}

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan repositories: %w", err)
	}

	return repoBlobs, repoTags, nil
}

func parseTagLinkPath(path string) (string, string, bool) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for index, part := range parts {
		if part != "_manifests" {
			continue
		}
		if index == 0 || index+4 >= len(parts) {
			return "", "", false
		}
		if parts[index+1] != "tags" || parts[index+3] != "current" || parts[index+4] != "link" {
			return "", "", false
		}
		return strings.Join(parts[:index], "/"), parts[index+2], true
	}
	return "", "", false
}

func readDigestLink(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read link %s: %w", path, err)
	}

	digest := strings.TrimSpace(string(data))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("unsupported digest %q", digest)
	}

	return digest, nil
}

func collectManifestReferences(v2Root, digest string, blobSizes map[string]int64, blobs map[string]struct{}, visited map[string]struct{}) error {
	if _, ok := visited[digest]; ok {
		return nil
	}
	visited[digest] = struct{}{}
	blobs[digest] = struct{}{}

	path, err := blobPath(v2Root, digest)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read manifest blob %s: %w", digest, err)
	}

	var manifest manifestDocument
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest blob %s: %w", digest, err)
	}

	addDescriptorBlob(manifest.Config, blobSizes, blobs)
	for _, layer := range manifest.Layers {
		addDescriptorBlob(layer, blobSizes, blobs)
	}

	for _, child := range manifest.Manifests {
		if child.Digest == "" {
			continue
		}
		if err := collectManifestReferences(v2Root, child.Digest, blobSizes, blobs, visited); err != nil {
			return err
		}
	}

	return nil
}

func addDescriptorBlob(descriptor manifestBlob, blobSizes map[string]int64, blobs map[string]struct{}) {
	if descriptor.Digest == "" {
		return
	}
	if _, ok := blobSizes[descriptor.Digest]; ok {
		blobs[descriptor.Digest] = struct{}{}
	}
}

func blobPath(v2Root, digest string) (string, error) {
	hexDigest, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexDigest) < 2 {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return filepath.Join(v2Root, "blobs", "sha256", hexDigest[:2], hexDigest, "data"), nil
}

func buildReport(blobSizes map[string]int64, repoBlobs map[string]map[string]struct{}, repoTags map[string]map[string]struct{}) *Report {
	blobRepositories := map[string]map[string]struct{}{}
	for repo, blobs := range repoBlobs {
		for blob := range blobs {
			if blobRepositories[blob] == nil {
				blobRepositories[blob] = map[string]struct{}{}
			}
			blobRepositories[blob][repo] = struct{}{}
		}
	}

	report := &Report{}
	for _, size := range blobSizes {
		report.TotalBlobBytes += size
	}

	referencedBlobs := map[string]struct{}{}
	for repo, blobs := range repoBlobs {
		usage := RepositoryUsage{
			Repository: repo,
			Tags:       sortedKeys(repoTags[repo]),
			BlobCount:  len(blobs),
		}

		for blob := range blobs {
			size := blobSizes[blob]
			usage.ReferencedBytes += size
			referencedBlobs[blob] = struct{}{}

			refCount := len(blobRepositories[blob])
			if refCount <= 1 {
				usage.ExclusiveBytes += size
				usage.ExclusiveBlobs++
				usage.AttributedBytes += float64(size)
				continue
			}

			usage.SharedBytes += size
			usage.SharedBlobs++
			usage.AttributedBytes += float64(size) / float64(refCount)
		}

		usage.ReferencedSize = FormatBytes(float64(usage.ReferencedBytes))
		usage.ExclusiveSize = FormatBytes(float64(usage.ExclusiveBytes))
		usage.SharedSize = FormatBytes(float64(usage.SharedBytes))
		usage.AttributedSize = FormatBytes(usage.AttributedBytes)

		report.Repositories = append(report.Repositories, usage)
	}

	for blob := range referencedBlobs {
		report.TotalReferencedBytes += blobSizes[blob]
	}
	report.UnreferencedBytes = report.TotalBlobBytes - report.TotalReferencedBytes
	report.TotalBlobSize = FormatBytes(float64(report.TotalBlobBytes))
	report.TotalReferencedSize = FormatBytes(float64(report.TotalReferencedBytes))
	report.UnreferencedSize = FormatBytes(float64(report.UnreferencedBytes))

	sort.Slice(report.Repositories, func(i, j int) bool {
		left := report.Repositories[i]
		right := report.Repositories[j]
		if math.Abs(left.AttributedBytes-right.AttributedBytes) > 0.0001 {
			return left.AttributedBytes > right.AttributedBytes
		}
		return left.Repository < right.Repository
	})

	return report
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
