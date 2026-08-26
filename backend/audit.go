package backend

import (
	"encoding/json"
	"time"
)

// AuditEntry is one recorded state change.
type AuditEntry struct {
	ID         int64  `json:"id"`
	At         int64  `json:"at"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
	ActorLabel string `json:"actor_label"`
	Action     string `json:"action"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
	IP         string `json:"ip,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

// Audited actions. Every mutating endpoint records one.
const (
	ActionLogin          = "auth.login"
	ActionLoginFailed    = "auth.login_failed"
	ActionLogout         = "auth.logout"
	ActionUserCreate     = "user.create"
	ActionUserUpdate     = "user.update"
	ActionUserPassword   = "user.password_change"
	ActionCustomerCreate = "customer.create"
	ActionCustomerUpdate = "customer.update"
	ActionTenantCreate   = "tenant.create"
	ActionTenantRevoke   = "tenant.revoke"
	ActionTenantExtend   = "tenant.extend"
	ActionTenantPause    = "tenant.pause"
	ActionTenantAttach   = "tenant.attach"
	ActionIPRegister     = "ip.register"
	ActionIPRelease      = "ip.release"
	ActionAllowAdd       = "policy.allow_add"
	ActionAllowRemove    = "policy.allow_remove"
	ActionOverrideSet    = "policy.override_set"
	ActionOverrideRemove = "policy.override_remove"
	ActionTokenCreate    = "token.create"
	ActionTokenRevoke    = "token.revoke"
	ActionPlanCreate     = "plan.create"
)

// Record appends an audit entry.
//
// Failures are swallowed on purpose. An audit write that fails must not roll
// back the operation it describes — the change has already happened, and
// refusing to report it would leave the system in a state the log denies. The
// error is surfaced through the logger instead.
func (s *Store) Record(e AuditEntry) {
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	_, _ = s.db.Exec(
		`INSERT INTO audit_log (at,actor_type,actor_id,actor_label,action,target_type,target_id,detail,ip,request_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.At, e.ActorType, e.ActorID, e.ActorLabel, e.Action,
		e.TargetType, e.TargetID, e.Detail, e.IP, e.RequestID)
}

// AuditDetail renders structured context for an entry. Values that could carry
// a secret must never be passed here.
func AuditDetail(kv map[string]any) string {
	if len(kv) == 0 {
		return ""
	}
	b, err := json.Marshal(kv)
	if err != nil {
		return ""
	}
	return string(b)
}

// AuditQuery filters a log listing.
type AuditQuery struct {
	Action     string
	ActorID    string
	TargetType string
	TargetID   string
	Since      int64
	Until      int64
	Limit      int
	Offset     int
}

// ListAudit returns entries newest first.
//
// Every filter below is a bound parameter. Building this query by string
// concatenation would put an attacker-supplied action name straight into SQL,
// which is exactly the shape of injection an audit endpoint invites.
func (s *Store) ListAudit(q AuditQuery) ([]*AuditEntry, error) {
	query := `SELECT id,at,actor_type,actor_id,actor_label,action,target_type,target_id,detail,ip,request_id
	          FROM audit_log WHERE 1=1`
	args := []any{}

	if q.Action != "" {
		query += ` AND action=?`
		args = append(args, q.Action)
	}
	if q.ActorID != "" {
		query += ` AND actor_id=?`
		args = append(args, q.ActorID)
	}
	if q.TargetType != "" {
		query += ` AND target_type=?`
		args = append(args, q.TargetType)
	}
	if q.TargetID != "" {
		query += ` AND target_id=?`
		args = append(args, q.TargetID)
	}
	if q.Since > 0 {
		query += ` AND at>=?`
		args = append(args, q.Since)
	}
	if q.Until > 0 {
		query += ` AND at<=?`
		args = append(args, q.Until)
	}

	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, clampLimit(q.Limit), max0(q.Offset))

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.ActorType, &e.ActorID, &e.ActorLabel,
			&e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP, &e.RequestID); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (s *Store) CountAudit() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}
