#!/usr/bin/env python
import subprocess
from datetime import datetime
import socket
import ssl
import nagiosplugin
from optparse import OptionParser


def timedelta_to_seconds(td):
    # python 2.7 has total_seconds, but we're using python 2.6
    return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6)


def seconds2human(s):
        """
        convert seconds to 'X days, Y hours and Z minutes'
        remaining seconds are ignored
        :param s: timespan in seconds
        :return: string
        """
        # cut off trailing s
        if 's' in str(s):
            s = int(s[:-1])
        days = s / 86400
        remainder = s % 86400
        hours = remainder / 3600
        remainder = hours % 3600
        minutes = remainder
        return "%d days, %d hours and %d minutes" % (days, hours, minutes)


class CertificateExpiry(nagiosplugin.Resource):
    name = "Certificate Expiry"

    def __init__(self, domain, port, timeout):
        self.domain = domain
        self.port = port
        self.timeout = timeout

    def probe(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        ssl_sock = ssl.wrap_socket(s)
        try:
            ssl_sock.connect((self.domain, self.port))
            addr = ssl_sock.getpeername()
            certificate = ssl.get_server_certificate(addr=addr)
        except socket.timeout:
            raise IOError("timeout connecting to %s" % self.domain)
        except:
            # provide a nice error message to caller
            raise IOError("cannot connect to %s" % self.domain)
        finally:
            ssl_sock.close()
        p1 = subprocess.Popen(["openssl", "x509", "-noout", "-enddate"],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)
        stdout, _ = p1.communicate(certificate)
        _, expirydate = stdout.split("=")
        expiry_date_in_seconds = ssl.cert_time_to_seconds(expirydate.strip())
        expiry_in_seconds = timedelta_to_seconds(datetime.fromtimestamp(expiry_date_in_seconds) - datetime.now())
        return nagiosplugin.Metric("expiry",
                                   value=expiry_in_seconds,
                                   uom="s",
                                   context="certificate_expiry")


class ExpirySummary(nagiosplugin.Summary):
    def ok(self, results):
        return "%s remaining" % seconds2human(str(results['expiry'].metric))

    def problem(self, results):
        return "%s remaining" % seconds2human(str(results['expiry'].metric))


@nagiosplugin.guarded
def main():
    parser = OptionParser()
    parser.add_option("-d", "--domain", dest="domain",
                      help="check certificate of DOMAIN", metavar="DOMAIN")
    parser.add_option("-p", "--port", dest="port",
                      help="destination PORT", metavar="PORT", type="int", default=443)
    parser.add_option("-t", "--timeout", dest="timeout",
                      help="set connection timeout to TIMEOUT",
                      metavar="TIMEOUT", type="int", default=5)
    parser.add_option("-w", "--warning", dest="warning",
                      help="warn if certificate is expiring in less than WARN seconds",
                      metavar="WARN", type="int")
    parser.add_option("-c", "--critical", dest="critical",
                      help="critical if certificate is expiring in less than CRITICAL seconds",
                      metavar="CRITICAL", type="int")
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="verbose output", action="count", default=0)
    options, args = parser.parse_args()

    if not options.domain:
        # exception is catched by nagiosplugin.guarded decorator
        raise ValueError("parameter DOMAIN must be specified")

    # create warning and critical range objects
    warning_range = nagiosplugin.Range("@%d:%d" % (options.warning, options.critical))
    critical_range = nagiosplugin.Range("%d" % options.critical)

    check = nagiosplugin.Check(
        CertificateExpiry(options.domain, options.port, options.timeout),
        nagiosplugin.ScalarContext("certificate_expiry", warning_range, critical_range),
        ExpirySummary()
    )
    check.main(verbose=options.verbose)


if __name__ == "__main__":
    main()
