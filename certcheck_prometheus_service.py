import win32serviceutil
import win32service
import win32event
import time
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime as dt
import binascii
import ssl
from prometheus_client import start_http_server, Gauge

# Define Prometheus metrics
expiring_cert_count = Gauge('certificates_expiring_soon', 'Number of certificates expiring within 30 days')
cert_expiration_date = Gauge('certificate_expiration_date', 'Expiration date of the certificate in timestamp format', ['serial_number'])
cert_issuer = Gauge('certificate_issuer', 'Issuer of the certificate', ['issuer'])
cert_fingerprint = Gauge('certificate_fingerprint', 'Fingerprint of the certificate', ['fingerprint'])

class CertificateService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CertCheckService"
    _svc_display_name_ = "Certificate Check Service"
    _svc_description_ = "Service that checks certificates and exposes metrics via Prometheus."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        start_http_server(8000)  # Start Prometheus metrics server
        logging.basicConfig(filename="service.log", level=logging.DEBUG)
        logging.debug("Service initialized and HTTP server started on port 8000")

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)
        logging.debug("Service stopping")

    def SvcDoRun(self):
        logging.debug("Service is running")
        self.main()

    def main(self):
        while self.running:
            self.check_certificates()
            time.sleep(3600)  # Check every X sec

    def check_certificates(self):
        date = dt.today()
        expiring_soon = 0
        logging.debug("Checking certificates")
        for store in ["CA", "ROOT"]:
            try:
                for cert, encoding, trust in ssl.enum_certificates(store):
                    certificate = x509.load_der_x509_certificate(cert, backend=default_backend())
                    expiration_date = certificate.not_valid_after
                    days_until_expiration = (expiration_date - date).days

                    if days_until_expiration < 30 :
                        expiring_soon += 1
                        issuer = str(certificate.issuer)
                        fingerprint = binascii.hexlify(certificate.fingerprint(hashes.SHA256())).decode()
                        serial_number = certificate.serial_number

                        # Log metrics being set
                        logging.debug(f"Updating metrics for serial_number={serial_number}, issuer={issuer}, fingerprint={fingerprint}")
                        cert_expiration_date.labels(serial_number=serial_number).set(expiration_date.timestamp())
                        cert_issuer.labels( issuer=issuer).set(1)  # Use 1 as a placeholder value
                        cert_fingerprint.labels(fingerprint=fingerprint).set(1)  # Use 1 as a placeholder value
            except Exception as e:
                logging.error(f"Error processing certificates from store {store}: {e}")
                
        expiring_cert_count.set(expiring_soon)  # Set the gauge with the count
        logging.info(f"Checked certificates. {expiring_soon} expiring soon.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        # Install the service with auto-startup type
        win32serviceutil.InstallService(
            CertificateService._svc_name_,
            CertificateService._svc_display_name_,
            startType=win32service.SERVICE_AUTO_START
        )
        win32serviceutil.StartService(CertificateService._svc_name_)
    else:
        # Handle command-line arguments normally
        win32serviceutil.HandleCommandLine(CertificateService)