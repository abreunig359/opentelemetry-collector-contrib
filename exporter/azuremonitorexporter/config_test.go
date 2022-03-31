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

package azuremonitorexporter

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configtest"
	"go.opentelemetry.io/collector/service/servicetest"
)

func TestLoadConfig(t *testing.T) {
	factories, err := componenttest.NopFactories()
	assert.Nil(t, err)

	factory := NewFactory()
	factories.Exporters[typeStr] = factory
	cfg, err := servicetest.LoadConfigAndValidate(filepath.Join("testdata", "config.yaml"), factories)

	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, len(cfg.Exporters), 2)

	exporter := cfg.Exporters[config.NewComponentID(typeStr)]
	assert.Equal(t, factory.CreateDefaultConfig(), exporter)

	exporter = cfg.Exporters[config.NewComponentIDWithName(typeStr, "2")].(*Config)
	assert.NoError(t, configtest.CheckConfigStruct(exporter))
	assert.Equal(
		t,
		&Config{
			ExporterSettings:   config.NewExporterSettings(config.NewComponentIDWithName(typeStr, "2")),
			Endpoint:           defaultEndpoint,
			InstrumentationKey: "abcdefg",
			MaxBatchSize:       100,
			MaxBatchInterval:   10 * time.Second,
			SeverityMapping:    defaultSeverityMapping,
		},
		exporter)
}
