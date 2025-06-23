# zapified

Zapified is a project developed to scan web applications with ZAP
during the development process, in order to find potential vulnerabilities before the app is deployed.


# Running  zapified
In order to run the project, you have to:
- [ ] have docker installed
- [ ] clone this repository with `git clone https://github.com/lisikava/zapified.git`
- [ ] create a virtual environment with `python -m venv .venv`
- [ ] run a virtual environment with `source .venv/bin/atcivate`
- [ ] install the required dependencies with `pip install -r requirements.txt`
- [ ] do `sudo docker run -u zap -p 8090:8090 --network="host" -i zaproxy/zap-stable  zap.sh -daemon -host 0.0.0.0 -port 8090   -config api.addrs.addr.name=.*   -config api.addrs.addr.regex=true -config api.key=change-me-9203935709
` to run the ZAP docker image 
- [ ] run the app you wish to scan. There is a sample Hello world app inside this project,
which you may run as an example with `python sample_app.py`
- [ ] finally, run the scanner with `python zapify.py`.
- [ ] alternatively, you can run cli tool with `python zapify_cli.py` 
It will report all the alerts received from the ZAP scan, as well as create a
`zap_report.json` file, which will contain the full report for the web app.