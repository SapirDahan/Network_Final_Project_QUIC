# Project: QUIC-Based Data Transmission System

## Overview

This project implements a **QUIC (Quick UDP Internet Connections)**-based data transmission system with a focus on fast and reliable data transfer between a client and server. **QUIC** is a transport layer network protocol that improves upon **TCP** by reducing latency, supporting multiplexed connections, and integrating encryption (TLS) by default.

The system features a **client-server architecture**, where the QUIC protocol is used to manage secure and efficient communication. While a file generator is included to produce large test files for transmission, the core focus of the project is the QUIC implementation.

## Components

1. **QUIC_Server.py**: 
   - Implements the server-side of the QUIC protocol.
   - Handles incoming QUIC connections, negotiates handshakes, and processes transmitted data.
   - The server ensures encrypted, reliable communication using QUIC's built-in TLS functionality.

2. **QUIC_Client.py**: 
   - Implements the client-side of the QUIC protocol.
   - Initiates connections to the server and transmits data using QUIC.
   - You can customize the client to send specific payloads or files to the server.

3. **QUIC_api.py**: 
   - A simple API layer built using **FastAPI**, which provides endpoints for managing file transmission over the QUIC connection.
   - While not essential to the core QUIC functionality, the API offers a flexible interface for interacting with the client-server system.

4. **File_Generation.py**: 
   - Generates large files for testing the transmission capabilities of the QUIC system.
   - This utility is primarily for creating initial test cases and does not contribute to the core system's functionality.

## Why QUIC?

QUIC is a transport protocol designed for speed, security, and efficiency, providing:

- **Reduced Latency**: QUIC combines the connection establishment and encryption handshake into one step, significantly reducing setup time.
- **Multiplexed Connections**: Unlike TCP, which suffers from head-of-line blocking, QUIC allows multiple streams of data to be transmitted simultaneously without waiting for each other.
- **Built-in Security**: QUIC integrates **TLS** encryption at the transport level, providing robust security for data transmission.

This project demonstrates these advantages by implementing a basic but functional system using QUIC for file and data transmission.

## Requirements

- Python 3.x
- Required libraries:
  - `aioquic`: Python library for QUIC.
  - `fastapi`: For building the API.
  - `uvicorn`: ASGI server for running FastAPI.
  - `pytest`: For running tests.

Install the dependencies using:

```bash
pip install aioquic fastapi uvicorn pytest
```

## Project Architecture

```
+------------------+                     +------------------+
|  QUIC Client      | --QUIC Protocol-->  |   QUIC Server     |
|  (QUIC_Client.py) |                     |  (QUIC_Server.py) |
+------------------+                     +------------------+
```

- **QUIC Server**: Listens for client connections and processes incoming data. The server also ensures encrypted data transmission.
- **QUIC Client**: Initiates the connection, sending data or files to the server. The payload can be customized as needed.
- **API (Optional)**: Provides a RESTful interface for triggering file transmission, but the main functionality lies within the QUIC client-server interaction.

## Setup and Running

1. **Start the QUIC Server**:
   Run the server to listen for incoming QUIC connections:

   ```bash
   python QUIC_Server.py
   ```

2. **Start the QUIC Client**:
   To initiate a connection to the server:

   ```bash
   python QUIC_Client.py
   ```

   You can modify the client to send specific data or interact with the server as needed.

3. **Run the API (Optional)**:
   If you want to interact with the system through a web interface:

   ```bash
   uvicorn QUIC_api:app --reload
   ```

   This starts a FastAPI server at `http://localhost:8000/` to manage file transmissions via RESTful endpoints.

## Running Tests

Run the tests to ensure the QUIC implementation and API function as expected:


## Example Workflow

1. Run the **QUIC server** (`python QUIC_Server.py`).
2. Initiate a **QUIC client** to connect to the server and transmit data (`python QUIC_Client.py`).
3. Optionally interact with the **FastAPI API** to trigger data transmissions and manage files.

## Future Enhancements

1. **Extend Client-Server Functionality**: Add more comprehensive data handling features such as file splitting and parallel transmissions.
2. **Security Improvements**: While QUIC already includes TLS, additional security layers like custom encryption for sensitive data could be explored.
3. **Performance Optimization**: Measure and optimize the performance of the QUIC client-server interaction for different file sizes and transmission conditions.

## File Structure

```
- QUIC_Server.py        # QUIC server-side implementation
- QUIC_Client.py        # QUIC client-side implementation
- QUIC_api.py           # FastAPI-based optional API
- File_Generation.py    # Utility for generating test files
- tests/                # Test cases for client-server communication and API
```
