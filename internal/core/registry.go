package core

import (
	"context"
	"strings"
	"time"
)

// RegistryOutput is the summary view over a batch of verifications: one row per
// document plus the counts an auditor reads first. It exists because auditing an
// archive or a migrated document store asks a different question than verifying
// one signature — "which of these 5000 are bad, and why" — and answering it from
// raw batch output means re-deriving the same summary in every consumer.
type RegistryOutput struct {
	CheckedAt time.Time `json:"checkedAt"`
	Total     int       `json:"total"`
	Valid     int       `json:"valid"`
	Invalid   int       `json:"invalid"`
	// Indeterminate counts documents whose checks could not be completed (an
	// unreachable responder, an unverifiable chain) — kept apart from Invalid so a
	// network problem is not read as a bad signature.
	Indeterminate int `json:"indeterminate"`
	// Failed counts items the service could not process at all (malformed input,
	// library error); their Error field says why.
	Failed int           `json:"failed"`
	Rows   []RegistryRow `json:"rows"`
}

// RegistryRow is one document in the register, flattened to what a reviewer scans:
// the verdict, who signed, when, and the reason when something is wrong.
type RegistryRow struct {
	Index    int              `json:"index"`
	Ref      string           `json:"ref,omitempty"` // caller's label for this document
	Verdict  ReportVerdict    `json:"verdict"`
	Summary  string           `json:"summary,omitempty"`
	Signers  []RegistrySigner `json:"signers,omitempty"`
	SignedAt *time.Time       `json:"signedAt,omitempty"`
	// Reason names the first failing or indeterminate check, so a reviewer can sort
	// a register by cause without opening each report.
	Reason   string          `json:"reason,omitempty"`
	Document ReportDocument  `json:"document"`
	Error    *BatchItemError `json:"error,omitempty"`
}

// RegistrySigner identifies a signer in a register row.
type RegistrySigner struct {
	Name         string `json:"name,omitempty"`
	IIN          string `json:"iin,omitempty"`
	BIN          string `json:"bin,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// RegistryItem is one document to check, with an optional caller label (a file
// name, a document id) echoed back in the row so the register maps onto the
// caller's own inventory.
type RegistryItem struct {
	Ref    string
	Verify VerifyInput
}

// VerifyRegistry verifies a set of documents and returns the register. It runs
// the same batch machinery as VerifyBatch — same concurrency, same policy — and
// summarizes the results; the report is requested per item regardless of what the
// caller set, since the register is built from it.
func (s *Service) VerifyRegistry(ctx context.Context, items []RegistryItem, opts BatchOptions) RegistryOutput {
	inputs := make([]VerifyInput, len(items))
	for i, it := range items {
		in := it.Verify
		in.Report = true
		inputs[i] = in
	}
	batch := s.VerifyBatch(ctx, inputs, opts, nil)

	out := RegistryOutput{CheckedAt: s.now(), Total: batch.Total, Rows: make([]RegistryRow, 0, len(batch.Results))}
	for _, item := range batch.Results {
		row := RegistryRow{Index: item.Index, Error: item.Error}
		if item.Index < len(items) {
			row.Ref = items[item.Index].Ref
		}
		if item.Output == nil {
			// No output at all: the item failed before a verdict could form.
			row.Verdict = VerdictIndeterminate
			out.Failed++
			if item.Error != nil {
				row.Summary, row.Reason = item.Error.Message, item.Error.Kind
			}
		} else {
			fillRowFromReport(&row, item.Output.Report)
			switch row.Verdict {
			case VerdictValid:
				out.Valid++
			case VerdictInvalid:
				out.Invalid++
			default:
				out.Indeterminate++
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}

// fillRowFromReport flattens a verification card into a register row.
func fillRowFromReport(row *RegistryRow, rep *VerificationReport) {
	if rep == nil {
		row.Verdict = VerdictIndeterminate
		return
	}
	row.Verdict, row.Summary, row.Document = rep.Verdict, rep.Summary, rep.Document
	for _, s := range rep.Signers {
		row.Signers = append(row.Signers, RegistrySigner{
			Name: s.Name, IIN: s.IIN, BIN: s.BIN, Organization: s.Organization,
		})
		if row.SignedAt == nil {
			row.SignedAt = s.SignedAt
		}
	}
	if rep.Verdict != VerdictValid {
		row.Reason = firstProblemStep(rep.Steps)
	}
}

// firstProblemStep names the first step that failed or could not be determined —
// the cause a reviewer groups a register by.
func firstProblemStep(steps []DiagnosisStep) string {
	for _, s := range steps {
		if s.Status == DiagFail || s.Status == DiagUnknown {
			return strings.TrimSpace(s.Step)
		}
	}
	return ""
}
