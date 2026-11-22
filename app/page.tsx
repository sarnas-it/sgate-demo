const layers = [
  {
    id: "sca",
    title: "SCA",
    product: "Deps",
    text: "Уязвимые версии пакетов, OSV, достижимость, план обновления.",
  },
  {
    id: "secrets",
    title: "Секреты и ПДн",
    product: "Guardrail",
    text: "Дифф PR: ключи, токены, пароли, персональные данные РФ.",
  },
  {
    id: "sast",
    title: "SAST",
    product: "Semgrep",
    text: "Небезопасные конструкции в коде — слой пилота.",
  },
  {
    id: "containers",
    title: "Контейнеры и IaC",
    product: "Trivy",
    text: "Образы, Dockerfile, конфигурация инфраструктуры.",
  },
];

export default function Page() {
  return (
    <main
      style={{
        maxWidth: 980,
        margin: "0 auto",
        padding: "64px 24px 96px",
      }}
    >
      <p
        style={{
          margin: 0,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          fontSize: 12,
          color: "#7f8db3",
        }}
      >
        Sarnas Security Gate · пилот
      </p>
      <h1 style={{ fontSize: 44, lineHeight: 1.1, margin: "12px 0 16px" }}>
        Один гейт на четыре проверки
      </h1>
      <p style={{ fontSize: 18, lineHeight: 1.6, color: "#b3bddb", maxWidth: 720 }}>
        Демонстрационный репозиторий: здесь намеренно оставлена уязвимая
        зависимость <code>next 16.3.8</code>, чтобы показать, как гейт
        блокирует релиз до исправления.
      </p>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
          gap: 16,
          marginTop: 40,
        }}
      >
        {layers.map((layer) => (
          <article
            key={layer.id}
            style={{
              border: "1px solid #243050",
              borderRadius: 16,
              padding: 20,
              background: "#101733",
            }}
          >
            <div style={{ fontSize: 12, color: "#6ee7b7", letterSpacing: "0.08em" }}>
              {layer.title.toUpperCase()}
            </div>
            <h2 style={{ fontSize: 20, margin: "8px 0 6px" }}>{layer.product}</h2>
            <p style={{ margin: 0, color: "#a9b5d8", lineHeight: 1.55, fontSize: 14 }}>
              {layer.text}
            </p>
          </article>
        ))}
      </section>

      <section style={{ marginTop: 40, color: "#8e9bc0", fontSize: 14, lineHeight: 1.7 }}>
        <p style={{ margin: 0 }}>
          Политика: CRITICAL/HIGH — блокировка, MODERATE — предупреждение,
          исключения — только с владельцем и сроком.
        </p>
      </section>
    </main>
  );
}
