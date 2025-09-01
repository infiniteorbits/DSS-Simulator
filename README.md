# DSS Simulator

## Prerequisites
- Linux
- [Docker](https://docs.docker.com/get-docker/) installed on your system.

## Usage

### 1. Clone the repository
```bash
git clone git@github.com:infiniteorbits/DSS-Simulator.git
cd DSS-Simulator
```
### 2. Build Image
``` bash
cd packaged_simulator
docker build -t name-of-your-image: version-of-your-image .
```
### 3. Run Image
```bash
docker run -it --cap-add=NET_ADMIN --privileged --net=host  name-of-your-image: version-of-your-image
```
