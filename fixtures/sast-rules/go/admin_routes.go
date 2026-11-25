package fixtures

// Router и Handler — минимальные заглушки: правило смотрит только на форму
// вызова, а не на конкретный фреймворк.
type Router interface {
	Get(path string, h Handler)
	Post(path string, h Handler)
	Route(path string, fn func(Router))
	With(mw Middleware) Router
	Use(mw Middleware)
}

type Handler func()
type Middleware func(Handler) Handler

func adminRoutes(r Router, h Handler, auth Middleware) {
	r.Get("/api/admin/users", h)            // ruleid: sgate-go-admin-route-without-middleware
	r.With(auth).Get("/api/admin/users", h) // ok: sgate-go-admin-route-without-middleware
	r.Get("/health", h)                     // ok: sgate-go-admin-route-without-middleware
	r.Post("/api/admin/users", h)           // ruleid: sgate-go-admin-route-without-middleware
	r.Get("/api/users", h)                  // ok: sgate-go-admin-route-without-middleware
	r.Get("/api/manage/settings", h)        // ruleid: sgate-go-admin-route-without-middleware
}

func adminGroupProtected(r Router, h Handler, auth Middleware) {
	r.Route("/api/admin", func(r Router) {
		r.Use(auth)
		r.Get("/users", h) // ok: sgate-go-admin-route-without-middleware
	})
}

func adminGroupOpen(r Router, h Handler) {
	r.Route("/api/admin", func(r Router) {
		r.Get("/users", h) // ruleid: sgate-go-admin-route-without-middleware
	})
}
