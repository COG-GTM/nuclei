# Playbook: Adding a New Issue Tracker Integration to Nuclei

This playbook walks through every file you need to create or modify to wire up a new issue tracker (e.g., "Acme Tracker") in the nuclei repository. The pattern is fully established by the existing trackers (GitHub, GitLab, Gitea, Jira, Linear).

---

## Architecture Overview

Every tracker implements the `Tracker` interface defined in `pkg/reporting/reporting.go`:

```go
// Tracker is an interface implemented by an issue tracker
type Tracker interface {
    // Name returns the name of the tracker
    Name() string
    // CreateIssue creates an issue in the tracker
    CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error)
    // CloseIssue closes an issue in the tracker
    CloseIssue(event *output.ResultEvent) error
    // ShouldFilter determines if the event should be filtered out
    ShouldFilter(event *output.ResultEvent) bool
}
```

The `ReportingClient` in `pkg/reporting/reporting.go` iterates over all registered trackers when a result event fires (in `CreateIssue()`). The `Client` interface (`pkg/reporting/client.go`) and the result-writing glue (`pkg/protocols/common/helpers/writer/writer.go`) do **not** need changes — they operate on the `Tracker` interface which your new integration automatically satisfies.

---

## Step-by-step guide

### 1. Create the tracker package

Create a new directory and Go file:

**`pkg/reporting/trackers/<yourtracker>/<yourtracker>.go`**

Use an existing tracker as your template. The simplest references are `gitea` (`pkg/reporting/trackers/gitea/gitea.go`) or `linear` (`pkg/reporting/trackers/linear/linear.go`). Your file must define:

| Construct | Purpose |
|---|---|
| `type Options struct` | YAML-deserializable config with fields like API key, project ID, etc. Include `AllowList`, `DenyList` (`*filters.Filter`), `DuplicateIssueCheck` (`bool`), `HttpClient` (`*retryablehttp.Client`, `yaml:"-"`), `OmitRaw` (`bool`, `yaml:"-"`). |
| `type Integration struct` | Holds the API client and options. |
| `func New(options *Options) (*Integration, error)` | Constructor — initializes the API client. |
| `func (i *Integration) Name() string` | Returns a lowercase tracker name, e.g. `"yourtracker"`. |
| `func (i *Integration) CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error)` | Formats and creates the issue. Return `IssueID` and `IssueURL`. |
| `func (i *Integration) CloseIssue(event *output.ResultEvent) error` | Closes an issue (can be a no-op stub initially). |
| `func (i *Integration) ShouldFilter(event *output.ResultEvent) bool` | Checks tracker-level allow/deny lists. |

#### Options struct

Follow the pattern from any existing tracker. For example, from `pkg/reporting/trackers/gitea/gitea.go`:

```go
type Options struct {
    BaseURL             string              `yaml:"base-url" validate:"omitempty,url"`
    Token               string              `yaml:"token" validate:"required"`
    ProjectOwner        string              `yaml:"project-owner" validate:"required"`
    ProjectName         string              `yaml:"project-name" validate:"required"`
    IssueLabel          string              `yaml:"issue-label"`
    SeverityAsLabel     bool                `yaml:"severity-as-label"`
    AllowList           *filters.Filter     `yaml:"allow-list"`
    DenyList            *filters.Filter     `yaml:"deny-list"`
    DuplicateIssueCheck bool                `yaml:"duplicate-issue-check" default:"false"`
    HttpClient          *retryablehttp.Client `yaml:"-"`
    OmitRaw             bool                `yaml:"-"`
}
```

#### CreateIssue

Use the format helpers to build the issue body:

```go
summary := format.Summary(event)
description := format.CreateReportDescription(event, util.MarkdownFormatter{}, i.options.OmitRaw)
```

These helpers are in `pkg/reporting/format/`. The `ResultFormatter` interface (`pkg/reporting/format/format.go`) provides formatting methods like `MakeBold`, `CreateCodeBlock`, `CreateTable`, `CreateLink`, and `CreateHorizontalLine`.

For duplicate-issue handling, follow the pattern of checking `DuplicateIssueCheck` before creating, and commenting on existing issues if a duplicate is found (see `pkg/reporting/trackers/gitea/gitea.go` for reference).

The `CreateIssueResponse` type lives in the filters package (`pkg/reporting/trackers/filters/filters.go`):

```go
type CreateIssueResponse struct {
    IssueID  string `json:"issue_id"`
    IssueURL string `json:"issue_url"`
}
```

#### ShouldFilter

Copy the standard boilerplate:

```go
func (i *Integration) ShouldFilter(event *output.ResultEvent) bool {
    if i.options.AllowList != nil && !i.options.AllowList.GetMatch(event) {
        return false
    }
    if i.options.DenyList != nil && i.options.DenyList.GetMatch(event) {
        return false
    }
    return true
}
```

---

### 2. Add the Options field to `pkg/reporting/options.go`

Add a new field for your tracker's `Options` to the `reporting.Options` struct:

```go
// YourTracker contains configuration options for YourTracker Issue Tracker
YourTracker *yourtracker.Options `yaml:"yourtracker"`
```

Add the corresponding import for your new package.

---

### 3. Wire up instantiation in `pkg/reporting/reporting.go`

In the `New()` function, add a block to instantiate your tracker when the config is present. Follow the existing pattern:

```go
if options.YourTracker != nil {
    options.YourTracker.HttpClient = options.HttpClient
    options.YourTracker.OmitRaw = options.OmitRaw
    tracker, err := yourtracker.New(options.YourTracker)
    if err != nil {
        return nil, errkit.Wrapf(err, "could not create reporting client: %v", ErrReportingClientCreation)
    }
    client.trackers = append(client.trackers, tracker)
}
```

Place it alongside the other tracker blocks in `New()`.

Also add it to `CreateConfigIfNotExists()` so the default config file template includes a placeholder:

```go
YourTracker: &yourtracker.Options{},
```

---

### 4. Update the example config YAML

Add a commented-out example to **`cmd/nuclei/issue-tracker-config.yaml`** showing all your tracker's config options. Follow the format of the existing entries.

---

### 5. Update test fixtures

Add your tracker config to the integration test YAML fixtures so the config-parsing logic is exercised:

- `internal/runner/testdata/test-issue-tracker-config2.yaml`
- `internal/tests/integration/testdata/test-issue-tracker-config1.yaml`
- `internal/tests/integration/testdata/test-issue-tracker-config2.yaml`

---

### 6. (Optional) Add unit tests

Create `pkg/reporting/trackers/<yourtracker>/<yourtracker>_test.go`. See `pkg/reporting/trackers/jira/jira_test.go` for a reference on how existing trackers are tested.

---

## Summary checklist

| # | File | Action |
|---|---|---|
| 1 | `pkg/reporting/trackers/<yourtracker>/<yourtracker>.go` | **Create** — `Options`, `Integration`, `New()`, `Name()`, `CreateIssue()`, `CloseIssue()`, `ShouldFilter()` |
| 2 | `pkg/reporting/options.go` | **Modify** — add `YourTracker *yourtracker.Options` field + import |
| 3 | `pkg/reporting/reporting.go` — `New()` | **Modify** — add instantiation block |
| 4 | `pkg/reporting/reporting.go` — `CreateConfigIfNotExists()` | **Modify** — add default empty options |
| 5 | `cmd/nuclei/issue-tracker-config.yaml` | **Modify** — add commented example config |
| 6 | `internal/runner/testdata/test-issue-tracker-config2.yaml` | **Modify** — add test config |
| 7 | `internal/tests/integration/testdata/test-issue-tracker-config*.yaml` | **Modify** — add test config |
| 8 | `pkg/reporting/trackers/<yourtracker>/<yourtracker>_test.go` | **Create** (optional) — unit tests |
