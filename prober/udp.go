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
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	crypt_rand "crypto/rand"
	"github.com/prometheus/blackbox_exporter/config"
	coap "github.com/rainbowfhb/go-coap"
	math_rand "math/rand"
)

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {

	if module.UDP.AppProtocol == "lwm2m" {
		return dialLwm2m(target, module, logger)
	}

	return false
}

func dialLwm2m(target string, module config.Module, logger log.Logger) bool {
	math_rand.Seed(time.Now().Unix())
	msgId := math_rand.Intn(65535)
	randByteArr := make([]byte, 4)
	_, err := crypt_rand.Read(randByteArr)
	if err != nil {
		level.Error(logger).Log("msg", "Error get rand byte", "err", err)
		return false
	}

	req := coap.Message{
		Type:      coap.Confirmable,
		Code:      coap.POST,
		MessageID: uint16(msgId),
		Token:     randByteArr,
		//Payload:   []byte("</>;ct=11543,</1/0>,</3/0>,</4/0>,</5/0>,</7/0>,</19/0>,</19/1>"),
	}
	req.SetPathString("/rd")
	req.AddOption(coap.ContentFormat, coap.AppLinkFormat)
	req.AddOption(coap.URIQuery, "b=U")
	req.AddOption(coap.URIQuery, "lwm2m=1.0")
	req.AddOption(coap.URIQuery, "lt=90")
	req.AddOption(coap.URIQuery, "ep="+module.UDP.IMEI)
	req.AddOption(coap.URIQuery, "apn=Psm0.eDRX0")
	req.AddOption(coap.URIQuery, "im=1.0")
	req.AddOption(coap.URIQuery, "ct=1.0")
	req.AddOption(coap.URIQuery, "mt=1.0")
	req.AddOption(coap.URIQuery, "mv=1.0")

	cp, err := coap.Dial("udp", target)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing", "err", err)
		return false
	}

	rv, err := cp.Send(req)
	if err != nil {
		level.Error(logger).Log("msg", "Error sending request", "err", err)
		return false
	}

	if rv != nil && rv.Code == 0 {
		level.Info(logger).Log("msg", "Send Response Code", "Code", rv.Code)
		rv, err := cp.Receive()
		if err != nil {
			level.Error(logger).Log("msg", "Receive Response Code", "err", err)
			return false
		}
		if rv != nil && rv.Code != coap.Created {
			level.Error(logger).Log("msg", "Receive Response Code", "rv", rv.Code)
			return false
		}
	} else if rv != nil && rv.Code != coap.Created {
		level.Error(logger).Log("msg", "Send Response Code", "rv", rv.Code)
		return false
	}
	/*
		if rv != nil && rv.Code != coap.Created {
			level.Error(logger).Log("msg", "Response Code", "rv", rv.Code)
			return false
		}
	*/

	math_rand.Seed(time.Now().Unix())
	dismsgId := math_rand.Intn(10000)

	disreq := coap.Message{
		Type:      coap.Confirmable,
		Code:      coap.DELETE,
		MessageID: uint16(dismsgId),
	}

	disreq.SetPathString("/rd/" + module.UDP.IMEI)
	disrv, err := cp.Send(disreq)
	if err != nil {
		level.Error(logger).Log("msg", "Error sending disconn request", "err", err)
		return false
	}

	if disrv != nil && disrv.Code != coap.Deleted {
		level.Error(logger).Log("msg", "Response Code", "disrv", disrv.Code)
		return false
	}

	cp.Disconnect()

	return true
}
