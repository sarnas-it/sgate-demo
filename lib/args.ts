import minimist from "minimist";

// Небольшой разбор аргументов для демонстрации: пакет намеренно уязвим.
export function parseArgs(argv: string[]) {
  return minimist(argv);
}
