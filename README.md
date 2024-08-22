# Heap Exploitation Guide

## Overview

This repository provides an in-depth exploration of heap exploitation techniques in the context of Linux-based operating systems, particularly focusing on the glibc memory allocator. It covers the fundamentals of heap memory management, common vulnerabilities, and advanced exploitation techniques. The content is derived from a detailed study and walk-through of various heap exploitation strategies, including practical examples.

## Contents

- **Introduction**
  - Overview of memory management in C/C++.
  - The role of ELF files in Linux and the process initialization.

- **Heap Fundamentals**
  - **Memory Allocation:** Explains how the operating system manages memory allocation through syscalls.
  - **Heap Allocators:** Overview of different memory allocators like `dlmalloc`, `ptmalloc`, `tcmalloc`, and `jemalloc`.
  - **Glibc Algorithm:** Detailed explanation of the ptmalloc algorithm used by glibc, including per-thread arenas and chunk management.

- **Heap Management & Structure**
  - Discussion on how heap memory is structured and managed in terms of allocated and free chunks.
  - Explanation of bins (Unsorted, Small, Large, Fast) and how they are used in memory allocation and deallocation.

- **Exploitation Techniques**
  - **Vulnerabilities:**
    - Use After Free
    - Double Free
    - Heap Overflow
  - **Bin Attacks:**
    - Fast Bin Attack
    - Unsorted Bin Attack
  - **Houses:**
    - House of Force

- **Practical Walk-through:**
  - Detailed walk-through of the `Asciigal` challenge, demonstrating heap exploitation in a real-world scenario.
  - Steps include information gathering, reverse engineering, planning the exploit, and executing the attack using Python scripts and the `pwntools` library.

## How to Use

1. **Clone the repository**:
   \```bash
   git clone https://github.com/your_username/heap-exploitation-guide.git
   \```

2. **Explore the Contents**:
   - Navigate through the provided sections to understand the theoretical aspects and practical examples of heap exploitation.

3. **Run the Examples**:
   - Use the provided Python scripts to replicate the exploitation techniques discussed in the guide.

## Requirements

- Basic knowledge of C/C++ programming.
- Familiarity with Linux operating system and ELF files.
- Understanding of memory management
