# Vulnerability Evaluation Framework


## Architecture Overview

                      ┌──────────────────────────┐
                      │  Ground Truth Generator  │
                      │  (OSV-based)             │
                      └───────────┬──────────────┘
                                  │
              Ground Truth (CSV)  │   SBOM (CycloneDX)
                                  │
                                  ▼
        ┌───────────────────────────────────────────────────┐
        │            Vulnerability Evaluation Framework     │
        │                                                   │
        │  ┌───────────────┐     ┌──────────────────────┐   │
        │  │ Ground Truth  │     │  Tool Adapter Layer  │   │
        │  │   Loader      │     │──────────────────────│   │
        │  └───────┬───────┘     │  Dependency-Track    │   │
        │          │             │  OSV Scanner         │   │
        │          │             │  GitHub Advisory DB  │   │
        │          │             └─────────┬────────────┘   │
        │          │                       │                │
        │          ▼                       ▼                │
        │   ┌───────────────────────────────────────────┐   │
        │   │        Normalized Finding Model           │   │
        │   │ (ecosystem, component, version, vuln-id)  │   │
        │   └───────────────────┬───────────────────────┘   │
        │                       │                           │
        │                       ▼                           │
        │   ┌───────────────────────────────────────────┐   │
        │   │            Evaluation Engine              │   │
        │   │      TP / FP / FN Computation             │   │
        │   └───────────────────┬───────────────────────┘   │
        │                       │                           │
        │                       ▼                           │
        │   ┌───────────────────────────────────────────┐   │               
        │   │  Tables, Metrics, Heuristic Quality       │   │
        │   └───────────────────────────────────────────┘   │
        └───────────────────────────────────────────────────┘



## 1. Objective and Scope

This project provides a **tool-agnostic evaluation framework** for systematically
evaluating **vulnerability scanners and SCA tools** against a **ground-truth dataset**.

The focus is **exclusively on vulnerabilities** and their **correct mapping** to:

- Ecosystem
- Component
- Version
- Vulnerability (OSV / CVE)

The framework is **not a scanner** and **not an SBOM generator**, but an
**evaluation and comparison tool**.

---

## 2. Core Artifacts

### 2.1 Ground Truth (CSV)

The ground-truth dataset serves as the **gold standard** for the evaluation.

Each row contains exactly one vulnerability assignment:

- Ecosystem
- Component
- Version
- OSV-ID
- optional CVE alias
- is_vulnerable = true

**Definition of the ground truth**

> For each selected component and exactly one version, the dataset contains
> all vulnerabilities that OSV lists as affecting that version **at build time**.

---

### 2.2 SBOM (CycloneDX)

The generated SBOM:

- contains **exactly the same components and versions** as the ground truth
- can be imported directly into Dependency-Track
- serves as input for the tools under evaluation

**Invariant**

> Every vulnerability in the ground truth refers to a component that is
> also present in the SBOM - and vice versa.

---

## 3. Supported Scanners (Adapters)

The framework uses an **adapter pattern** to evaluate different scanners in a
uniform way.

### 3.1 Currently integrated adapters

| Adapter | Description |
|------|-------------|
| Dependency-Track | Classic SBOM-based SCA scanner |
| OSV | OSV as a standalone scanner |
| GitHub Advisory DB | GitHub Security Advisories (GHSA) |

All adapters produce **normalized findings** in the same internal model.

---

## 5. False-Positive Heuristic

The FP heuristic analyzes, among others:

- Ecosystem consistency
- Name match
- CPE match
- Foreign products (OS, browsers, servers, appliances)
- Execution context vs. library

### 5.1 FP-Class (Subtype)

| FP-Class | Meaning |
|--------|----------|
| ecosystem | CVE belongs to a different ecosystem |
| foreign | CVE affects a foreign product |
| name | Component name not listed in the advisory |
| cpe | CPEs do not match the component |
| types | Type packages (`@types/*`) |

A finding without an FP-Class is considered **heuristically correct**.

---

## 6. Evaluation Metrics

### 6.1 Classical metrics

| Metric | Meaning |
|------|----------|
| TP | True Positives |
| FP | False Positives |
| FN | False Negatives |

Derived:

- Recall = TP / (TP + FN)
- Overlap Rate = TP / (TP + FP)

---

### 6.2 Heuristic Quality Matrix

This matrix evaluates **the heuristic**, not the scanner.

| Metric | Meaning |
|--------|----------|
| HTP | FP correctly identified |
| HFN | FP missed |
| HFP | TP incorrectly flagged as FP |
| HTN | TP correctly not flagged |

Derived metrics:

- Heuristic Precision = HTP / (HTP + HFP)
- Heuristic Recall = HTP / (HTP + HFN)

These metrics are **only produced** when the adapter supports an FP heuristic.

---

## 7. Report - Tables and Meaning

### 7.1 Common columns

| Column | Meaning |
|------|----------|
| # | Sequential number |
| Ecosystem | e.g. pypi, npm |
| Component | Normalized package name |
| Version | Exact version |
| CVE-ID | CVE alias (if available) |
| OSV-ID | Primary advisory ID |
| Description | Description provided by the tool |

---

### 7.2 Additional heuristic columns

| Column | Meaning |
|------|----------|
| FP-Class | Heuristic subtype |
| FP-Reason | Textual justification |
| Heuristic-FP | yes / no |

---

## 8. Tables in Detail

### 8.1 False Positives (tool findings not in Ground Truth)

- Reported by the tool
- Not present in the ground truth
- Candidates for:
  - Over-detection
  - Misassignment
  - Imprecise heuristics

---

### 8.2 False Negatives (Ground Truth missed by tool)

- Present in the ground truth
- **Not** reported by the tool

**Why is the description empty?**

- FN entries have no tool finding
- Descriptions come exclusively from tool data
- No implicit enrichment from OSV (methodologically clean)

---

### 8.3 True Positives (Correct Matches)

- Tool finding matches the ground truth exactly

---

### 8.4 Findings marked as FP by heuristic

- All findings flagged as FP by the heuristic
- Regardless of whether they are TP or FP in the ground-truth sense

This table is central to evaluating the heuristic.

---

## 9. Methodological Clarification

- The ground truth decides TP / FP / FN
- The heuristic decides the flagging
- Both are kept **strictly separate**

> A heuristic is a hypothesis - not a truth.

---

## 10. Extensibility

The framework is prepared for:

- additional ecosystems (npm, maven, nuget)
- additional scanners with an open API
- additional heuristics
- alternative ground-truth definitions

---

## 11. Conclusion

- Results are reproducible and transparent
- Heuristics are measurable
- Scanners are comparable
- Methodological separation remains traceable at all times
