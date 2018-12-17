// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	MQTT "github.com/eclipse/paho.mqtt.golang"
	"github.com/prometheus/blackbox_exporter/config"
)

var msgInfo MQTT.Message

func dialTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (net.Conn, error) {
	var dialProtocol, dialTarget string
	dialer := &net.Dialer{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return nil, err
	}

	ip, _, err := chooseProtocol(module.TCP.PreferredIPProtocol, targetAddress, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "tcp6"
	} else {
		dialProtocol = "tcp4"
	}

	if len(module.TCP.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.TCP.SourceIPAddress)
		if srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.TCP.SourceIPAddress)
			return nil, fmt.Errorf("Error parsing source ip address: %s", module.TCP.SourceIPAddress)
		}
		level.Info(logger).Log("msg", "Using local address", "srcIP", srcIP)
		dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
	}

	dialTarget = net.JoinHostPort(ip.String(), port)

	if !module.TCP.TLS {
		level.Info(logger).Log("msg", "Dialing TCP without TLS")
		return dialer.DialContext(ctx, dialProtocol, dialTarget)
	}
	tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating TLS configuration", "err", err)
		return nil, err
	}

	if len(tlsConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// targetAddress as TLS-servername. Normally tls.DialWithDialer
		// would do this for us, but we pre-resolved the name by
		// `chooseProtocol` and pass the IP-address for dialing (prevents
		// resolving twice).
		// For this reason we need to specify the original targetAddress
		// via tlsConfig to enable hostname verification.
		tlsConfig.ServerName = targetAddress
	}
	timeoutDeadline, _ := ctx.Deadline()
	dialer.Deadline = timeoutDeadline

	level.Info(logger).Log("msg", "Dialing TCP with TLS")
	return tls.DialWithDialer(dialer, dialProtocol, dialTarget, tlsConfig)
}

func ProbeTCP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	deadline, _ := ctx.Deadline()

	if module.TCP.AppProtocol == "MQTT" {
		return dialMQTT(target, module, registry, logger)
	} else if module.TCP.AppProtocol == "TLink" {
		return dialTlink(target, module, registry, logger)
	}

	conn, err := dialTCP(ctx, target, module, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing TCP", "err", err)
		return false
	}
	defer conn.Close()
	level.Info(logger).Log("msg", "Successfully dialed")

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		level.Error(logger).Log("msg", "Error setting deadline", "err", err)
		return false
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
	}
	scanner := bufio.NewScanner(conn)
	for i, qr := range module.TCP.QueryResponse {
		level.Info(logger).Log("msg", "Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect != "" {
			re, err := regexp.Compile(qr.Expect)
			if err != nil {
				level.Error(logger).Log("msg", "Could not compile into regular expression", "regexp", qr.Expect, "err", err)
				return false
			}
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				level.Debug(logger).Log("msg", "Read line", "line", scanner.Text())
				match = re.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					level.Info(logger).Log("msg", "Regexp matched", "regexp", re, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				level.Error(logger).Log("msg", "Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				level.Error(logger).Log("msg", "Regexp did not match", "regexp", re, "line", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if send != "" {
			level.Debug(logger).Log("msg", "Sending line", "line", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				level.Error(logger).Log("msg", "Failed to send", "err", err)
				return false
			}
		}
		if qr.StartTLS {
			// Upgrade TCP connection to TLS.
			tlsConfig, err := pconfig.NewTLSConfig(&module.TCP.TLSConfig)
			if err != nil {
				level.Error(logger).Log("msg", "Failed to create TLS configuration", "err", err)
				return false
			}
			if tlsConfig.ServerName == "" {
				// Use target-hostname as default for TLS-servername.
				targetAddress, _, _ := net.SplitHostPort(target) // Had succeeded in dialTCP already.
				tlsConfig.ServerName = targetAddress
			}
			tlsConn := tls.Client(conn, tlsConfig)
			defer tlsConn.Close()

			// Initiate TLS handshake (required here to get TLS state).
			if err := tlsConn.Handshake(); err != nil {
				level.Error(logger).Log("msg", "TLS Handshake (client) failed", "err", err)
				return false
			}
			level.Info(logger).Log("msg", "TLS Handshake (client) succeeded.")
			conn = net.Conn(tlsConn)
			scanner = bufio.NewScanner(conn)

			// Get certificate expiry.
			state := tlsConn.ConnectionState()
			registry.MustRegister(probeSSLEarliestCertExpiry)
			probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
		}
	}
	return true
}

func dialMQTT(target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	var loginStatus bool
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return false
	}

	var targetUrl string
	if module.TCP.TLS {
		targetUrl = "tls://" + targetAddress + ":" + port
	} else {
		targetUrl = "tcp://" + targetAddress + ":" + port
	}

	opts := MQTT.NewClientOptions().AddBroker(targetUrl)
	opts.SetClientID(module.TCP.ClientID)
	opts.SetUsername(module.TCP.UserName)
	opts.SetPassword(module.TCP.PassWord)
	opts.SetCleanSession(false)
	//默认不传，paho使用MQTT 3.1.1连接服务端，如果连接报错，会再次用MQTT 3.1连接服务端；传值3，使用MQTT 3.1连接，让paho在连接失败的时候不再去重复连
	opts.SetProtocolVersion(3)
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.WaitTimeout(module.Timeout) {
		if token.Wait() && token.Error() != nil {
			level.Error(logger).Log("msg", "Error connect to mqtt server", "err", token.Error())
			if c.IsConnected() {
				c.Disconnect(250)
			}
			return false
		}
	} else {
		level.Error(logger).Log("msg", "Error io timeout", "err", targetUrl)
		if c.IsConnected() {
			c.Disconnect(250)
		}
		return false
	}

	if c.IsConnected() {
		c.Disconnect(250)
	}
	return true
}

func dialTlink(target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	var loginStatus bool

	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return false
	}

	var targetUrl string
	if module.TCP.TLS {
		targetUrl = "tls://" + targetAddress + ":" + port
	} else {
		targetUrl = "tcp://" + targetAddress + ":" + port
	}

	opts := MQTT.NewClientOptions().AddBroker(targetUrl)
	opts.SetClientID(module.TCP.ClientID)

	if module.TCP.UserName == "" {
		var buffer bytes.Buffer
		buffer.WriteString("\x00\x00\xA3\xA4")
		buffer.WriteString("\x01")
		buffer.WriteString("\x22\x55")
		buffer.WriteString("\x00\x00\x00\x00\x5a\x71\x7c\x95")
		buffer.WriteString("\x01")
		buffer.WriteString("\x00\x35")
		buffer.WriteString("\x00\x02\x09")
		buffer.WriteString("\x01")
		buffer.WriteString("\x00\x042.03")
		buffer.WriteString("\x00\x04U880")

		opts.SetUsername(base64.StdEncoding.EncodeToString([]byte(buffer.String())))
	} else {
		opts.SetUsername(base64.StdEncoding.EncodeToString([]byte(module.TCP.UserName)))
	}

	opts.SetPassword(base64.StdEncoding.EncodeToString([]byte("\x01\x00\x2b" + module.TCP.PassWord)))

	opts.SetCleanSession(true)
	opts.SetDefaultPublishHandler(on_message)
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.WaitTimeout(module.Timeout) {
		if token.Wait() && token.Error() != nil {
			level.Error(logger).Log("msg", "Error connect to tlink server", "err", token.Error())
			if c.IsConnected() {
				c.Disconnect(250)
			}
			return false
		}
	} else {
		level.Error(logger).Log("msg", "Error io timeout", "err", targetUrl)
		if c.IsConnected() {
			c.Disconnect(250)
		}
		return false
	}

	time.Sleep(5 * time.Second) //sleep for deal with server message
	if msgInfo == nil {
		level.Error(logger).Log("msg", "cannot get v1/dn/da response")
		if c.IsConnected() {
			c.Disconnect(250)
		}
		return false
	}
	level.Debug(logger).Log("msg", "get tlink response", "topic", msgInfo.Topic(), "payload%d", msgInfo.Payload())
	if msgInfo != nil && msgInfo.Topic() == "v1/dn/da" {
		switch msgInfo.Payload()[7] {
		case 0:
			level.Debug(logger).Log("msg", "login successfully")
			loginStatus = true
		case 1:
			level.Error(logger).Log("msg", "other reasons")
		case 2:
			level.Error(logger).Log("msg", "subscription failure")
		case 3:
			level.Error(logger).Log("msg", "auth failure")
		default:
			level.Error(logger).Log("msg", "donot match")
		}
	}

	if c.IsConnected() {
		c.Disconnect(250)
	}
	return loginStatus
}

func on_message(c MQTT.Client, msg MQTT.Message) {
	msgInfo = msg
}
