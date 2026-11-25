package fixtures

type DB interface {
	Query(q string) error
}

func dangerousSQL(db DB) {
	q := "SELECT * FROM url('http://169.254.169.254/latest/meta-data/')" // ruleid: sgate-go-sql-dangerous-function
	_ = db.Query(q)
	q = "SELECT * FROM file('/etc/passwd')" // ruleid: sgate-go-sql-dangerous-function
	_ = db.Query(q)
	q = "SELECT * FROM orders" // ok: sgate-go-sql-dangerous-function
	_ = db.Query(q)
	q = "update user profile" // ok: sgate-go-sql-dangerous-function
	_ = db.Query(q)
}
