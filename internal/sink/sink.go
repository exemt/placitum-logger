package sink

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/model"
)

const insertSQL = `INSERT INTO waf.audit (
	ts, node, ray, phase, rev,
	client_ip, client_port, server_ip, server_port, tls_version, tls_sni,
	method, scheme, host, uri, http_version,
	args_size, headers_size, headers_count, body_size, content_type, status,
	upstream_status,
	server_name, location, location_id,
	verdict, code, verdict_by,
	score, deny_at, shadow, waf_latency_us,
	inspectors, inspectors_verdict, inspectors_state, inspectors_score,
	inspectors_latency_ms, inspectors_role,
	inspectors_profile,
	vars,
	store_headers, store_args, store_body,
	headers_preview, args_preview, body_preview,
	headers_preview_truncated, args_preview_truncated,
	headers_preview_dropped, args_preview_dropped,
	actions, rewrite,
	frame_seq, frame_direction, frame_opcode, frame_size, frame_fin,
	frame_rewritten, frame_preview, frame_preview_truncated,
	session_frames_c2s, session_frames_s2c, session_bytes_c2s, session_bytes_s2c,
	session_denied, session_rewritten, session_close_code, session_close_reason,
	session_duration_ms,
	sessions_by, sessions_source, sessions_kind, sessions_user, sessions_id,
	sessions_verified, sessions_issued, sessions_expires, sessions_groups,
	sessions_passive,
	markers
)`

const insertFindingSQL = `INSERT INTO waf.audit_finding (
	ts, node, ray, phase, rev,
	inspector, profile, verdict, score, engine_ms,
	finding_idx, code, severity, target, rule,
	offset, length, confidence, evidence, message, tags,
	engine,
	frame_direction, frame_seq
)`

func Insert(ctx context.Context, conn driver.Conn, rows []model.Row) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := conn.PrepareBatch(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.TS,
			row.Node,
			row.Ray,
			row.Phase,
			row.Rev,

			row.ClientIP,
			row.ClientPort,
			row.ServerIP,
			row.ServerPort,
			row.TLSVersion,
			row.TLSSNI,

			row.Method,
			row.Scheme,
			row.Host,
			row.URI,
			row.HTTPVersion,

			row.ArgsSize,
			row.HeadersSize,
			row.HeadersCount,
			row.BodySize,
			row.ContentType,
			row.Status,
			row.UpstreamStatus,

			row.ServerName,
			row.Location,
			row.LocationID,

			row.Verdict,
			row.Code,
			row.VerdictBy,

			row.Score,
			row.DenyAt,
			row.Shadow,
			row.WAFLatencyUs,

			row.Inspectors,
			row.InspectorsVerdict,
			row.InspectorsState,
			row.InspectorsScore,
			row.InspectorsLatencyMs,
			row.InspectorsRole,
			row.InspectorsProfile,

			row.Vars,

			row.StoreHeaders,
			row.StoreArgs,
			row.StoreBody,

			row.HeadersPreview,
			row.ArgsPreview,
			row.BodyPreview,
			row.HeadersPreviewTruncated,
			row.ArgsPreviewTruncated,
			row.HeadersPreviewDropped,
			row.ArgsPreviewDropped,
			row.Actions,
			row.Rewrite,

			row.FrameSeq,
			row.FrameDirection,
			row.FrameOpcode,
			row.FrameSize,
			row.FrameFin,
			row.FrameRewritten,
			row.FramePreview,
			row.FramePreviewTruncated,
			row.SessionFramesC2S,
			row.SessionFramesS2C,
			row.SessionBytesC2S,
			row.SessionBytesS2C,
			row.SessionDenied,
			row.SessionRewritten,
			row.SessionCloseCode,
			row.SessionCloseReason,
			row.SessionDurationMs,

			row.SessionsBy,
			row.SessionsSource,
			row.SessionsKind,
			row.SessionsUser,
			row.SessionsID,
			row.SessionsVerified,
			row.SessionsIssued,
			row.SessionsExpires,
			row.SessionsGroups,
			row.SessionsPassive,

			row.Markers,
		); err != nil {
			return fmt.Errorf("append: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	return nil
}

func InsertFindings(ctx context.Context, conn driver.Conn, rows []model.FindingRow) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := conn.PrepareBatch(ctx, insertFindingSQL)
	if err != nil {
		return fmt.Errorf("prepare findings: %w", err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.TS,
			row.Node,
			row.Ray,
			row.Phase,
			row.Rev,

			row.Inspector,
			row.Profile,
			row.Verdict,
			row.Score,
			row.EngineMS,

			row.FindingIdx,
			row.Code,
			row.Severity,
			row.Target,
			row.Rule,

			row.Offset,
			row.Length,
			row.Confidence,
			row.Evidence,
			row.Message,
			row.Tags,

			row.Engine,

			row.FrameDirection,
			row.FrameSeq,
		); err != nil {
			return fmt.Errorf("append finding: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send findings: %w", err)
	}

	return nil
}
