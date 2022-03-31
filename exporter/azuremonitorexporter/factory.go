// Copyright OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azuremonitorexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/azuremonitorexporter"

import (
	"context"
	"errors"
	"time"

	"github.com/microsoft/ApplicationInsights-Go/appinsights"
	"github.com/microsoft/ApplicationInsights-Go/appinsights/contracts"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config"
	"go.uber.org/zap"
)

const (
	// The value of "type" key in configuration.
	typeStr         = "azuremonitor"
	defaultEndpoint = "https://dc.services.visualstudio.com/v2/track"
)

var (
	errUnexpectedConfigurationType = errors.New("failed to cast configuration to Azure Monitor Config")
	defaultSeverityMapping         = SeverityMappingConfig{
		Verbose:     []string{contracts.Verbose.String()},
		Information: []string{contracts.Information.String()},
		Warning:     []string{contracts.Warning.String()},
		Error:       []string{contracts.Error.String()},
		Critical:    []string{contracts.Critical.String()},
	}
)

// NewFactory returns a factory for Azure Monitor exporter.
func NewFactory() component.ExporterFactory {
	f := &factory{}
	return component.NewExporterFactory(
		typeStr,
		createDefaultConfig,
		component.WithTracesExporter(f.createTracesExporter),
		component.WithLogsExporter(f.createLogsExporter))
}

// Implements the interface from go.opentelemetry.io/collector/exporter/factory.go
type factory struct {
	tChannel transportChannel
}

func createDefaultConfig() config.Exporter {
	return &Config{
		ExporterSettings: config.NewExporterSettings(config.NewComponentID(typeStr)),
		Endpoint:         defaultEndpoint,
		MaxBatchSize:     1024,
		MaxBatchInterval: 10 * time.Second,
		SeverityMapping:  defaultSeverityMapping,
	}
}

func (f *factory) createTracesExporter(
	ctx context.Context,
	set component.ExporterCreateSettings,
	cfg config.Exporter,
) (component.TracesExporter, error) {
	exporterConfig, ok := cfg.(*Config)

	if !ok {
		return nil, errUnexpectedConfigurationType
	}

	tc := f.getTransportChannel(exporterConfig, set.Logger)
	return newTracesExporter(exporterConfig, tc, set)
}

func (f *factory) createLogsExporter(
	ctx context.Context,
	set component.ExporterCreateSettings,
	cfg config.Exporter,
) (component.LogsExporter, error) {
	exporterConfig, ok := cfg.(*Config)

	if !ok {
		return nil, errUnexpectedConfigurationType
	}

	tc := f.getTransportChannel(exporterConfig, set.Logger)
	return newLogsExporter(exporterConfig, tc, set)
}

// Configures the transport channel.
// This method is not thread-safe
func (f *factory) getTransportChannel(exporterConfig *Config, logger *zap.Logger) transportChannel {

	// The default transport channel uses the default send mechanism from the AppInsights telemetry client.
	// This default channel handles batching, appropriate retries, and is backed by memory.
	if f.tChannel == nil {
		telemetryConfiguration := appinsights.NewTelemetryConfiguration(exporterConfig.InstrumentationKey)
		telemetryConfiguration.EndpointUrl = exporterConfig.Endpoint
		telemetryConfiguration.MaxBatchSize = exporterConfig.MaxBatchSize
		telemetryConfiguration.MaxBatchInterval = exporterConfig.MaxBatchInterval
		telemetryClient := appinsights.NewTelemetryClientFromConfig(telemetryConfiguration)

		f.tChannel = telemetryClient.Channel()

		// Don't even bother enabling the AppInsights diagnostics listener unless debug logging is enabled
		if checkedEntry := logger.Check(zap.DebugLevel, ""); checkedEntry != nil {
			appinsights.NewDiagnosticsMessageListener(func(msg string) error {
				logger.Debug(msg)
				return nil
			})
		}
	}

	return f.tChannel
}
