/**
 * src/lib/quiz.ts
 *
 * Quiz questions for each vulnerability class shown after a developer accept/reject.
 * Separated from finding detail UI so it can be imported without pulling in React.
 */

export type VulnClass = "sqli" | "xss" | "csrf" | "insecure_deserialization" | "other";

export interface QuizQuestion {
  question: string;
  options: string[];
  correctIndex: number;
}

export const QUIZ_DATA: Record<VulnClass, QuizQuestion> = {
  sqli: {
    question: "Why do parameterized queries prevent SQL injection?",
    options: [
      "They encrypt the input before reaching the database",
      "The query structure is parsed before user data is bound — input can never become SQL syntax",
      "They strip all quotes from user input",
      "They run queries in a read-only transaction",
    ],
    correctIndex: 1,
  },
  xss: {
    question: "What is the safest default way to render user text in a React component?",
    options: [
      "dangerouslySetInnerHTML with a regex filter",
      "Plain JSX interpolation — React escapes HTML output by default",
      "innerHTML after replacing <script> tags",
      "Base64-encoding the text first",
    ],
    correctIndex: 1,
  },
  csrf: {
    question: "Why doesn't SameSite=Lax cookie alone fully replace CSRF tokens?",
    options: [
      "SameSite is ignored by mobile browsers",
      "Legacy clients, top-level GET navigations, and subdomains still send cookies — a token proves intent",
      "CSRF tokens are encrypted, cookies are not",
      "SameSite only works over HTTP/2",
    ],
    correctIndex: 1,
  },
  insecure_deserialization: {
    question: "Why is JSON preferred over pickle/node-serialize for untrusted input?",
    options: [
      "JSON is faster to parse",
      "JSON describes data only — it has no mechanism to construct objects or execute code during parsing",
      "pickle is deprecated since Python 3.10",
      "JSON automatically validates types",
    ],
    correctIndex: 1,
  },
  other: {
    question: "Which of the following correctly prevents command injection when running an OS process?",
    options: [
      "Escaping shell metacharacters with a regex before passing to exec()",
      "Using a fixed argument array (e.g. execFile(['cmd', arg])) so no shell is invoked",
      "Running the command in a Docker container",
      "Sanitising the input by removing spaces and semicolons",
    ],
    correctIndex: 1,
  },
};

/** Returns null if no quiz exists for the given class. */
export function getQuiz(vulnClass: string | undefined | null): QuizQuestion | null {
  if (!vulnClass) return null;
  return QUIZ_DATA[vulnClass as VulnClass] ?? QUIZ_DATA.other;
}
