# Contributing to SecureX

Thank you for your interest in contributing to **SecureX**! By contributing, you help improve security, usability, and documentation for everyone.

---

## 1. Getting Started

1. **Fork the repository**  
   Click the fork button on GitHub to create your own copy.

2. **Clone your fork**  
   ```bash
   git clone https://github.com/your-username/secureX.git
   cd secureX
   ```

3. **Install dependencies**

   ```bash
   npm install
   ```

4. **Build the project**

   ```bash
   npm run build
   ```

---

## 2. Branching & Commits

* Create a feature branch:

  ```bash
  git checkout -b feature/my-feature
  ```
* Follow **semantic commit messages**:

  * `feat:` New feature
  * `fix:` Bug fix
  * `chore:` Maintenance, build, version bump
  * `docs:` Documentation only
  * `test:` Adding or fixing tests

---

## 3. Coding Guidelines

* Project uses **ES Modules** (`.mjs`)
* Follow **consistent formatting** and **clean code**
* Write **unit tests** for critical functions under `test/`
* Test your code:

  ```bash
  npm test
  ```

---

## 4. Pull Requests

1. Push your branch to your fork:

   ```bash
   git push origin feature/my-feature
   ```
2. Open a Pull Request to `main` branch
3. PR must include:

   * Description of changes
   * Related issues (if any)
   * Test results (if applicable)
4. PR will be reviewed by a Maintainer or Core Team member
5. Once approved, your PR will be merged

> Note: Major changes (API, algorithms, or breaking changes) **require Core Team Lead approval**.

---

## 5. Reporting Issues

* Use GitHub Issues to report **bugs**, **suggestions**, or **security concerns**
* For security vulnerabilities, refer to [`SECURITY.md`](./SECURITY.md)

---

## 6. Code of Conduct

All contributors must follow the [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) rules.

---

Thanks for helping make **SecureX** better! 🎉