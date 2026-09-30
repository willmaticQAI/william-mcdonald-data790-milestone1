# DATA 790 Milestone 1 — Production RAG System

**William McDonald**  
DATA 790: Advanced AI Frameworks in Production  
University of North Carolina at Chapel Hill

## Overview

This project implements a compact production-style **Retrieval-Augmented Generation (RAG)** system over a controlled, course-focused corpus. The goal of Milestone 1 is to establish a measurable baseline that can be evaluated, documented, and hardened in later milestones.

The system:

- chunks and embeds source content,
- stores embeddings in a Chroma vector database,
- retrieves the top relevant chunks for a question,
- generates grounded answers with `gpt-4o-mini`,
- returns source chunk IDs and section metadata,
- performs basic input and prompt-injection checks,
- evaluates retrieval and answer quality,
- tracks latency and token usage,
- and estimates production inference cost.

## Architecture

```text
Course Corpus
    ↓
Chunking Comparison
    ↓
Embeddings
    ↓
Chroma Vector Store
    ↓
User Question
    ↓
Input Validation
    ↓
Top-3 Retrieval
    ↓
Retrieved Context
    ↓
gpt-4o-mini
    ↓
Answer + Source Chunk IDs
    ↓
Evaluation / Latency / Cost
```

The notebook also includes an optional support check that can retry retrieval with `k=5` when an answer is judged partially supported or unsupported.

## Design Choices

| Component | Implementation | Rationale |
|---|---|---|
| Corpus | 10 structured course sections with stable metadata | Keeps the baseline controlled and makes attribution and evaluation explicit |
| Chunking | 180 characters with 30-character overlap | Selected empirically from three tested strategies |
| Embeddings | `text-embedding-3-small` | Course-supported semantic embedding model through the UNC AI Gateway |
| Vector store | Chroma with cosine similarity | Lightweight local development, strong benchmark recall, and low local latency |
| Retrieval | Top-3 chunks | Balances context coverage against prompt size |
| Generation | `gpt-4o-mini`, temperature `0` | Appropriate for grounded QA with low latency and low projected cost |
| Attribution | Chunk ID + source section | Makes retrieved evidence visible for debugging and evaluation |
| Guardrails | Pattern-based input validation | Provides a simple Milestone 1 prompt-injection defense baseline |

## Chunking Experiment

Three chunking configurations were evaluated using the same 22-question golden set.

| Strategy | Chunk Size / Overlap | Chunks | Precision@3 | Recall@3 | Hit Rate@3 |
|---|---:|---:|---:|---:|---:|
| Small | 180 / 30 | 21 | **0.485** | **1.000** | **1.000** |
| Medium | 320 / 60 | 11 | 0.333 | 1.000 | 1.000 |
| Large | 600 / 100 | 10 | 0.333 | 1.000 | 1.000 |

The **small** strategy was selected because it maintained perfect top-3 retrieval coverage while improving precision.

## Evaluation Results

The final evaluation contains:

- **10 manually written questions**
- **10 AI-assisted questions verified against the corpus**
- **2 edge-case questions**

| Metric | Final Run |
|---|---:|
| Precision@3 | **0.485** |
| Recall@3 | **1.000** |
| Hit Rate@3 | **1.000** |
| Average concept score | **0.909** |
| Average LLM judge score | **0.841** |
| Average retrieval latency | **5.42 ms** |
| Average generation latency | **869.27 ms** |

### Metric Notes

- **Precision@3** measures the fraction of the top three returned chunks that belong to the expected source section.
- **Recall@3** is `1` when at least one expected-section chunk appears in the top three.
- **Hit Rate@3** uses the same binary criterion in this baseline because each question maps to one expected section.
- **Concept score** checks whether expected answer concepts appear in the generated response.
- **LLM judge score** grades answers as `0`, `0.5`, or `1`.

## Cost Analysis

The notebook tracks prompt and completion token usage for the primary generation call.

| Item | Estimate |
|---|---:|
| Average prompt tokens / query | 189.45 |
| Average completion tokens / query | 16.77 |
| Estimated generation cost / query | $0.0000385 |
| Projected volume | 10,000 queries / month |
| Projected monthly generation cost | $0.3848 |
| Example cache hit rate | 20% |
| Estimated monthly cache savings | $0.0770 |
| Projected cost after cache | $0.3079 |

These values are a **class cost projection** using the same pricing snapshot used in Lab 3. The UNC AI Gateway is prepaid. The projection covers the primary answer-generation call and does not include embedding requests, judge calls, optional support checks, storage, or infrastructure overhead.

## Repository Structure

```text
.
├── README.md
├── william_mcdonald_milestone_1_updated.ipynb
├── William_McDonald_Milestone_1_Report_REVISED.pdf
├── requirements.txt
├── .env.example
└── .gitignore
```

> If your notebook currently has a different filename, either rename it to `william_mcdonald_milestone_1_updated.ipynb` or update the commands below to match the committed filename.

## Setup

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_DIRECTORY>
```

### 2. Create and activate a virtual environment

The project was developed with Python 3.12.

**macOS / Linux**

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The notebook uses the following primary Python packages:

- `openai`
- `python-dotenv`
- `numpy`
- `pandas`
- `matplotlib`
- `chromadb`

### 4. Configure environment variables

Copy the example environment file:

```bash
cp .env.example .env
```

Then edit `.env`:

```env
UNC_AI_API_KEY=your_unc_ai_gateway_key_here
UNC_CHAT_MODEL=gpt-4o-mini
```

Do **not** commit your real `.env` file or API key.

## Running the Project

Start Jupyter:

```bash
jupyter lab
```

Open:

```text
william_mcdonald_milestone_1_updated.ipynb
```

Then run the notebook **top to bottom**.

The notebook performs the full workflow:

1. environment and API setup,
2. corpus creation,
3. chunking comparison,
4. embedding generation,
5. Chroma vector-store creation,
6. retrieval,
7. grounded generation,
8. source attribution,
9. retrieval evaluation,
10. answer evaluation,
11. cost analysis,
12. security checks,
13. failure analysis.

## Reproducibility / Full Evaluation Run

Because the evaluation is implemented directly in the notebook, running all cells executes the full evaluation pipeline.

For a non-interactive reproducibility check, Jupyter can execute the notebook from the command line:

```bash
jupyter nbconvert \
  --to notebook \
  --execute william_mcdonald_milestone_1_updated.ipynb \
  --output william_mcdonald_milestone_1_executed.ipynb
```

A successful run should complete without execution errors and produce the retrieval, answer-quality, latency, and cost tables described above.

## Source Attribution

Each generated answer is returned with the retrieved source chunk IDs and section metadata.

Example:

```text
ANSWER:
Returning sources makes the evidence used by the system visible.

SOURCES:
- chunk 15 | evaluation
- chunk 14 | generation
- chunk 17 | security
```

This attribution is part of the RAG pipeline rather than a post-processing citation layer.

## Security Baseline

Milestone 1 includes basic input validation before retrieval. The validator checks for:

- empty input,
- excessively long input,
- common instruction-override patterns,
- developer-mode style prompt injection attempts,
- requests intended to expose hidden instructions.

Retrieved content is also explicitly treated as **data rather than trusted instructions** in the system prompt.

These controls are intentionally limited. Comprehensive security hardening is reserved for Milestone 2.

## Known Limitations

This is a baseline RAG implementation, not a finished production service.

Current limitations include:

- character-based chunks can split sentences or terms,
- Chroma is ephemeral and local,
- API retry/backoff is not implemented,
- input security is rule-based,
- the evaluation set is small and course-specific,
- no persistent storage or production monitoring is included,
- cost estimates exclude several supporting API and infrastructure operations.

## Milestone 2 Priorities

The next milestone will focus on hardening the baseline through:

- stronger prompt-injection defenses,
- access control,
- output filtering,
- persistent storage,
- logging and auditability,
- structured error handling and retries,
- expanded evaluation,
- monitoring and operational controls.

## Technical Report

The full architecture rationale, evaluation methodology, failure analysis, and cost discussion are documented in:

```text
William_McDonald_Milestone_1_Report_REVISED.pdf
```

## Academic Context

This repository was created for **DATA 790 — Advanced AI Frameworks in Production** at the University of North Carolina at Chapel Hill.

The project is intentionally scoped as a measurable Milestone 1 baseline. Later coursework extends the system toward security hardening, deployment, monitoring, and production readiness.
