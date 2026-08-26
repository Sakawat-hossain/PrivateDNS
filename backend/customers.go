package backend

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Customer is the person who pays. A tenant is the DNS identity they use.
//
// They are separate records because one customer may hold several tenants, and
// because a tenant can be revoked and reissued without disturbing the account
// or its history.
type Customer struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	OwnerID   int64  `json:"owner_id"`
	Status    string `json:"status"`
	Notes     string `json:"notes,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`

	passwordHash string
}

func (c *Customer) Active() bool { return c != nil && c.Status == "active" }

func (s *Store) CreateCustomer(email, name, phone string, ownerID int64) (*Customer, error) {
	now := time.Now().Unix()
	email = strings.ToLower(strings.TrimSpace(email))

	res, err := s.db.Exec(
		`INSERT INTO customers (email,name,phone,owner_id,status,created_at,updated_at)
		 VALUES (?,?,?,?,'active',?,?)`,
		email, name, phone, ownerID, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()

	return &Customer{
		ID: id, Email: email, Name: name, Phone: phone,
		OwnerID: ownerID, Status: "active", CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Store) CustomerByID(id int64) (*Customer, error) {
	return scanCustomer(s.db.QueryRow(
		`SELECT id,email,name,phone,password_hash,owner_id,status,notes,created_at,updated_at
		 FROM customers WHERE id=?`, id))
}

func (s *Store) CustomerByEmail(email string) (*Customer, error) {
	return scanCustomer(s.db.QueryRow(
		`SELECT id,email,name,phone,password_hash,owner_id,status,notes,created_at,updated_at
		 FROM customers WHERE email=? AND email<>''`,
		strings.ToLower(strings.TrimSpace(email))))
}

func scanCustomer(row *sql.Row) (*Customer, error) {
	var c Customer
	err := row.Scan(&c.ID, &c.Email, &c.Name, &c.Phone, &c.passwordHash,
		&c.OwnerID, &c.Status, &c.Notes, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListCustomers returns customers visible to a principal.
//
// A reseller sees only the customers it owns. This is the isolation boundary
// that matters commercially: resellers compete with one another, and one
// reading another's customer list would be a direct business harm.
func (s *Store) ListCustomers(p *Principal, limit, offset int) ([]*Customer, error) {
	query := `SELECT id,email,name,phone,owner_id,status,created_at,updated_at FROM customers`
	args := []any{}

	if !p.IsAdmin() {
		query += ` WHERE owner_id=?`
		args = append(args, p.UserID)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, clampLimit(limit), max0(offset))

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Customer
	for rows.Next() {
		var c Customer
		if err := rows.Scan(&c.ID, &c.Email, &c.Name, &c.Phone, &c.OwnerID,
			&c.Status, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// CanAccessCustomer decides whether a principal may act on a customer.
func (s *Store) CanAccessCustomer(p *Principal, customerID int64) (bool, error) {
	if p.IsAdmin() {
		return true, nil
	}

	if p.Role == RoleCustomer {
		return p.CustomerID != 0 && customerID == p.CustomerID, nil
	}

	var owner int64
	err := s.db.QueryRow(`SELECT owner_id FROM customers WHERE id=?`, customerID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return owner == p.UserID, nil
}

func (s *Store) UpdateCustomer(id int64, name, phone, notes, status string) error {
	_, err := s.db.Exec(
		`UPDATE customers SET name=?, phone=?, notes=?, status=?, updated_at=? WHERE id=?`,
		name, phone, notes, status, time.Now().Unix(), id)
	return err
}

func (s *Store) SetCustomerPassword(id int64, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE customers SET password_hash=?, updated_at=? WHERE id=?`,
		hash, time.Now().Unix(), id)
	return err
}

func (c *Customer) VerifyPassword(password string) error {
	if c == nil || c.passwordHash == "" {
		// No password set. Return the same error a wrong password gives, so
		// the response does not distinguish the two cases.
		return ErrInvalidCredentials
	}
	return VerifyPassword(password, c.passwordHash)
}

// ---- customer/tenant association ----

func (s *Store) AttachTenant(routeID string, customerID int64) error {
	_, err := s.db.Exec(
		`INSERT INTO customer_tenants (route_id,customer_id,created_at) VALUES (?,?,?)
		 ON CONFLICT(route_id) DO UPDATE SET customer_id=excluded.customer_id`,
		strings.ToLower(routeID), customerID, time.Now().Unix())
	return err
}

func (s *Store) DetachTenant(routeID string) error {
	_, err := s.db.Exec(`DELETE FROM customer_tenants WHERE route_id=?`, strings.ToLower(routeID))
	return err
}

func (s *Store) TenantOwner(routeID string) (customerID int64, err error) {
	err = s.db.QueryRow(`SELECT customer_id FROM customer_tenants WHERE route_id=?`,
		strings.ToLower(routeID)).Scan(&customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return customerID, err
}

func (s *Store) TenantsForCustomer(customerID int64) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT route_id FROM customer_tenants WHERE customer_id=? ORDER BY created_at`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CanAccessTenant is the tenant-level isolation check.
//
// It resolves the tenant to its customer and then to that customer's owner. An
// unattached tenant is admin-only, which is the safe default: a tenant with no
// recorded owner must not become visible to whoever asks first.
func (s *Store) CanAccessTenant(p *Principal, routeID string) (bool, error) {
	if p.IsAdmin() {
		return true, nil
	}

	customerID, err := s.TenantOwner(routeID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if p.Role == RoleCustomer {
		// Compare against the linked customer record, never the user id.
		return p.CustomerID != 0 && customerID == p.CustomerID, nil
	}
	return s.CanAccessCustomer(p, customerID)
}

// ---- plans ----

type Plan struct {
	ID         int64  `json:"id"`
	Code       string `json:"code"`
	Name       string `json:"name"`
	Days       int    `json:"days"`
	Minutes    int    `json:"minutes"`
	PriceMinor int64  `json:"price_minor"`
	Currency   string `json:"currency"`
	Active     bool   `json:"active"`
}

// Duration is how long this plan grants access for.
func (p *Plan) Duration() time.Duration {
	return time.Duration(p.Days)*24*time.Hour + time.Duration(p.Minutes)*time.Minute
}

func (s *Store) CreatePlan(code, name string, days, minutes int, priceMinor int64, currency string) (*Plan, error) {
	if currency == "" {
		currency = "BDT"
	}
	res, err := s.db.Exec(
		`INSERT INTO plans (code,name,days,minutes,price_minor,currency,active,created_at)
		 VALUES (?,?,?,?,?,?,1,?)`,
		code, name, days, minutes, priceMinor, currency, time.Now().Unix())
	if err != nil {
		if isUnique(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Plan{ID: id, Code: code, Name: name, Days: days, Minutes: minutes,
		PriceMinor: priceMinor, Currency: currency, Active: true}, nil
}

func (s *Store) PlanByCode(code string) (*Plan, error) {
	var p Plan
	var active int
	err := s.db.QueryRow(
		`SELECT id,code,name,days,minutes,price_minor,currency,active FROM plans WHERE code=?`,
		code).Scan(&p.ID, &p.Code, &p.Name, &p.Days, &p.Minutes, &p.PriceMinor, &p.Currency, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Active = active != 0
	return &p, nil
}

func (s *Store) ListPlans(includeInactive bool) ([]*Plan, error) {
	query := `SELECT id,code,name,days,minutes,price_minor,currency,active FROM plans`
	if !includeInactive {
		query += ` WHERE active=1`
	}
	query += ` ORDER BY days, minutes`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Plan
	for rows.Next() {
		var p Plan
		var active int
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Days, &p.Minutes,
			&p.PriceMinor, &p.Currency, &active); err != nil {
			return nil, err
		}
		p.Active = active != 0
		out = append(out, &p)
	}
	return out, rows.Err()
}

func clampLimit(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 500:
		return 500
	default:
		return n
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
