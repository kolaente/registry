package main

import (
	"bytes"
	"strings"
	"testing"

	usagepkg "github.com/kolaente/registry/pkg/usage"
)

func TestWriteUsageTableKeepsSizeColumnsReadableWithManyTags(t *testing.T) {
	report := &usagepkg.Report{
		Repositories: []usagepkg.RepositoryUsage{
			{
				Repository:     "alpaca-software/gpt-services/test-static-html",
				Tags:           []string{"latest", "main", "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0"},
				AttributedSize: "47.1 MiB",
				ReferencedSize: "47.1 MiB",
				ExclusiveSize:  "47.1 MiB",
				SharedSize:     "0 B",
				BlobCount:      28,
			},
		},
		TotalBlobSize:       "113 GiB",
		TotalReferencedSize: "113 GiB",
		UnreferencedSize:    "0 B",
	}

	var output bytes.Buffer
	writeUsageTable(&output, report, 3)

	rendered := output.String()
	lines := strings.Split(rendered, "\n")
	header := strings.Fields(lines[0])
	if strings.Join(header, ",") != "REPOSITORY,ATTRIBUTED,REFERENCED,EXCLUSIVE,SHARED,BLOBS,TAGS" {
		t.Fatalf("header does not keep size columns before tags:\n%s", rendered)
	}
	if !strings.Contains(rendered, "47.1 MiB") || !strings.Contains(rendered, "28     latest,main,v1.0.0,+4 more") {
		t.Fatalf("row does not summarize tags after size columns:\n%s", rendered)
	}
}

func TestBuildInfoStringIncludesCommit(t *testing.T) {
	got := buildInfoString("dev", "abc1234")
	want := "version=dev commit=abc1234"

	if got != want {
		t.Fatalf("buildInfoString() = %q, want %q", got, want)
	}
}
