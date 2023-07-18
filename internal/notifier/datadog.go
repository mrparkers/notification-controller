/*
Copyright 2023 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
)

type DataDog struct {
	apiClient *datadog.APIClient
	eventsApi *datadogV1.EventsApi
	apiKey    string
	env       string
}

func NewDataDog(env string, proxyUrl string, certPool *x509.CertPool, apiKey string) (*DataDog, error) {
	conf := datadog.NewConfiguration()

	if apiKey == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	if proxyUrl != "" || certPool != nil {
		transport := &http.Transport{}

		if proxyUrl != "" {
			proxy, err := url.Parse(proxyUrl)
			if err != nil {
				return nil, fmt.Errorf("failed to parse proxy URL %q: %w", proxyUrl, err)
			}

			transport.Proxy = http.ProxyURL(proxy)
		}

		if certPool != nil {
			transport.TLSClientConfig = &tls.Config{
				RootCAs: certPool,
			}
		}

		conf.HTTPClient = &http.Client{
			Transport: transport,
		}
	}

	apiClient := datadog.NewAPIClient(conf)
	eventsApi := datadogV1.NewEventsApi(apiClient)

	return &DataDog{
		apiClient,
		eventsApi,
		apiKey,
		env,
	}, nil
}

func (d *DataDog) Post(ctx context.Context, event eventv1.Event) error {
	fmt.Printf("token: %s\n", d.apiKey)

	dataDogEvent := d.toDataDogEvent(&event)

	_, _, err := d.eventsApi.CreateEvent(d.dataDogCtx(ctx), dataDogEvent)
	if err != nil {
		return fmt.Errorf("failed to post event to DataDog: %w", err)
	}

	return nil
}

func (d *DataDog) dataDogCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {
			Key: d.apiKey,
		},
	})
}

func (d *DataDog) toDataDogEvent(event *eventv1.Event) datadogV1.EventCreateRequest {
	return datadogV1.EventCreateRequest{
		Title: fmt.Sprintf("%s/%s.%s", strings.ToLower(event.InvolvedObject.Kind), event.InvolvedObject.Name, event.InvolvedObject.Namespace),
		Text:  event.Message,
		Tags: []string{
			fmt.Sprintf("controller:%s", event.ReportingController),
			fmt.Sprintf("env:%s", d.env),
		},
		SourceTypeName: strPtr("fluxcd"),
		DateHappened:   int64Ptr(event.Timestamp.Unix()),
		AlertType:      toDataDogAlertType(event),
	}
}

func toDataDogAlertType(event *eventv1.Event) *datadogV1.EventAlertType {
	if event.Severity == eventv1.EventSeverityError {
		return dataDogEventAlertTypePtr(datadogV1.EVENTALERTTYPE_ERROR)
	}

	return dataDogEventAlertTypePtr(datadogV1.EVENTALERTTYPE_INFO)
}

func dataDogEventAlertTypePtr(t datadogV1.EventAlertType) *datadogV1.EventAlertType {
	return &t
}
