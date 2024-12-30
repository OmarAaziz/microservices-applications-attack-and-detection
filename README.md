# Microservice Attacks and Detection Ecosystem

This repository hosts the implementation and documentation for the **Microservice Attacks and Detection Ecosystem (Microservice Att and DE)** project. The goal is to develop a solution for detecting and mitigating attacks on microservice architectures while generating a comprehensive dataset for research and analysis.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Setup and Installation](#setup-and-installation)
    - [Prerequisites](#prerequisites)
    - [Steps](#steps)
4. [Usage](#usage)
5. [Project Structure](#project-structure)
6. [Contributing](#contributing)
7. [License](#license)
8. [Acknowledgments](#acknowledgments)

---

## Project Overview

This project aims to address the challenges in detecting and preventing attacks in microservice architectures. The primary objectives include:
- Simulating diverse microservice-specific attacks.
- Collecting logs to build a dataset for research and detection purposes.
- Developing and comparing machine learning models for anomaly detection.
- Providing a scalable, extensible framework for future improvements in microservice security.

### Key Deliverables:
1. A comprehensive attack dataset.
2. Machine learning models for attack detection.
3. A working prototype demonstrating detection capabilities.

---

## Features

- **Automated Microservice Deployment**: Uses Kubernetes to deploy microservices across multiple nodes and pods.
- **Attack Simulation**:
  - API abuse.
  - Container escape attacks.
  - Denial-of-service (DoS) attacks.
  - Network sniffing.
- **Dataset Generation**: Logs generated during simulations are structured for machine learning and research.
- **Anomaly Detection Models**: Implements machine learning algorithms for real-time and batch attack detection.
- **Scalability**: Supports integration with additional attack modules and detection algorithms.

---

## Setup and Installation

### Prerequisites

To set up the environment, ensure the following are installed:
- **Operating System**: Fedora or other Linux-based distributions.
- **Required Software**:
  - Docker
  - Kubernetes (kubectl and minikube are recommended)
  - Python (version 3.8 or higher)
  - Sysdig (for monitoring and logging)

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/microservice-att-de.git
   cd microservice-att-de

