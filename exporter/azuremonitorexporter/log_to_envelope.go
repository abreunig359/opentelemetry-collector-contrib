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
	stdlibErrors "errors"
	"strconv"
	"time"

	"github.com/microsoft/ApplicationInsights-Go/appinsights/contracts"
	"go.opentelemetry.io/collector/model/pdata"
	"go.uber.org/zap"
)

// errNoSuccessAttrAvailable should be returned when no attribute with key "success" is available in attributes
var errNoSuccessAttrAvailable = stdlibErrors.New("no success attribute available")

const (
	traceIDTag                                = "TraceId"
	spanIDTag                                 = "SpanId"
	applicationInsightsTelemetryTypeAttribute = "ApplicationInsightsTelemetryType"
	durationAttributeKey                      = "duration"
	responseCodeAttributeKey                  = "responseCode"
	resultCodeAttributeKey                    = "resultCode"
	successAttribute                          = "success"
)

type AiTelemetryType string

const (
	ApplicationInsightsTelemetryTypeDependency AiTelemetryType = "Dependency"
	ApplicationInsightsTelemetryTypeRequest    AiTelemetryType = "Request"
	ApplicationInsightsTelemetryTypeEvent      AiTelemetryType = "Event"
	ApplicationInsightsTelemetryTypeMessage    AiTelemetryType = "Message"
)

var severityLevelMap = map[string]contracts.SeverityLevel{
	"Verbose":     contracts.Verbose,
	"Information": contracts.Information,
	"Warning":     contracts.Warning,
	"Error":       contracts.Error,
	"Critical":    contracts.Critical,
}

type logPacker struct {
	logger *zap.Logger
}

func (packer *logPacker) LogRecordToEnvelope(logRecord pdata.LogRecord) *contracts.Envelope {
	// default to telemetry type message (application insights trace) to stay backwards compatible with original implementation
	telemetryType := ApplicationInsightsTelemetryTypeMessage
	if telemetryTypeAttribute, ok := logRecord.Attributes().Get(applicationInsightsTelemetryTypeAttribute); ok {
		telemetryType = toAiTelemetryType(telemetryTypeAttribute.StringVal())
	}

	envelope := contracts.NewEnvelope()
	envelope.Tags = make(map[string]string)
	envelope.Time = toTime(logRecord.Timestamp()).Format(time.RFC3339Nano)
	envelope.Tags[contracts.OperationId] = logRecord.TraceID().HexString()

	data := contracts.NewData()
	var dataSanitizeFunc func() []string

	switch telemetryType {
	case ApplicationInsightsTelemetryTypeMessage:
		messageData := packer.logToMessageData(logRecord)
		envelope.Name = messageData.EnvelopeName("")
		data.BaseData = messageData
		data.BaseType = messageData.BaseType()
		dataSanitizeFunc = messageData.Sanitize
	case ApplicationInsightsTelemetryTypeRequest:
		requestData := logToRequestData(logRecord)
		dataSanitizeFunc = requestData.Sanitize
		envelope.Name = requestData.EnvelopeName("")
		envelope.Tags[contracts.OperationName] = requestData.Name
		data.BaseData = requestData
		data.BaseType = requestData.BaseType()
	case ApplicationInsightsTelemetryTypeDependency:
		dependencyData := logToDependencyData(logRecord)
		dataSanitizeFunc = dependencyData.Sanitize
		envelope.Name = dependencyData.Name
		envelope.Tags[contracts.OperationName] = dependencyData.Name
		data.BaseData = dependencyData
		data.BaseType = dependencyData.BaseType()
	}

	envelope.Data = data

	packer.sanitize(dataSanitizeFunc)
	packer.sanitize(func() []string { return envelope.Sanitize() })
	packer.sanitize(func() []string { return contracts.SanitizeTags(envelope.Tags) })

	return envelope
}

func (packer *logPacker) sanitize(sanitizeFunc func() []string) {
	for _, warning := range sanitizeFunc() {
		packer.logger.Warn(warning)
	}
}

func (packer *logPacker) toAiSeverityLevel(severityText string) contracts.SeverityLevel {
	if severityLevel, ok := severityLevelMap[severityText]; ok {
		return severityLevel
	}

	packer.logger.Warn("Unknown Severity Level", zap.String("Severity Level", severityText))
	return contracts.Verbose
}

func toAiTelemetryType(applicationInsightsAttribute string) AiTelemetryType {
	switch applicationInsightsAttribute {
	case string(ApplicationInsightsTelemetryTypeDependency):
		return ApplicationInsightsTelemetryTypeDependency
	case string(ApplicationInsightsTelemetryTypeRequest):
		return ApplicationInsightsTelemetryTypeDependency
	case string(ApplicationInsightsTelemetryTypeEvent):
		return ApplicationInsightsTelemetryTypeEvent
	default:
		return ApplicationInsightsTelemetryTypeMessage
	}
}

// Maps logRecord to AppInsights MessageData
func (packer *logPacker) logToMessageData(logRecord pdata.LogRecord) *contracts.MessageData {
	messageData := contracts.NewMessageData()
	messageData.Properties = make(map[string]string)

	messageData.SeverityLevel = packer.toAiSeverityLevel(logRecord.SeverityText())

	messageData.Message = logRecord.Body().StringVal()

	hexTraceID := logRecord.TraceID().HexString()
	messageData.Properties[traceIDTag] = hexTraceID

	messageData.Properties[spanIDTag] = logRecord.SpanID().HexString()

	return messageData
}

func logToRequestData(logRecord pdata.LogRecord) *contracts.RequestData {
	data := contracts.NewRequestData()
	data.Id = logRecord.TraceID().HexString()

	if durationAttribute, ok := logRecord.Attributes().Get(durationAttributeKey); ok {
		data.Duration = durationAttribute.StringVal()
	}

	data.ResponseCode = getResponseOrResultCode(logRecord.Attributes(), responseCodeAttributeKey)
	if success, err := getSuccessFromAttributes(logRecord.Attributes()); err != nil {
		data.Success = success
	}
	data.Properties = make(map[string]string)
	data.Measurements = make(map[string]float64)

	// re-using span type since we need the same values
	incomingSpanType := mapIncomingSpanToType(logRecord.Attributes())
	switch incomingSpanType {
	case httpSpanType:
		fillRequestDataHTTP(logRecord.Attributes(), "", data)
	case rpcSpanType:
		fillRequestDataRPC(logRecord.Attributes(), data)
	case messagingSpanType:
		fillRequestDataMessaging(logRecord.Attributes(), data)
	case unknownSpanType:
		copyAttributesWithoutMapping(logRecord.Attributes(), data.Properties, data.Measurements)
	}

	return data
}

func logToDependencyData(logRecord pdata.LogRecord) *contracts.RemoteDependencyData {
	data := contracts.NewRemoteDependencyData()
	data.Id = logRecord.TraceID().HexString()

	data.ResultCode = getResponseOrResultCode(logRecord.Attributes(), resultCodeAttributeKey)
	if success, err := getSuccessFromAttributes(logRecord.Attributes()); err != nil {
		data.Success = success
	}

	data.Properties = make(map[string]string)
	data.Measurements = make(map[string]float64)

	// re-using span type since we need the same values
	incomingSpanType := mapIncomingSpanToType(logRecord.Attributes())
	switch incomingSpanType {
	case httpSpanType:
		fillRemoteDependencyDataHTTP(logRecord.Attributes(), data)
	case rpcSpanType:
		fillRemoteDependencyDataRPC(logRecord.Attributes(), data)
	case databaseSpanType:
		fillRemoteDependencyDataDatabase(logRecord.Attributes(), data)
	case messagingSpanType:
		fillRemoteDependencyDataMessaging(logRecord.Attributes(), data)
	case unknownSpanType:
		copyAttributesWithoutMapping(logRecord.Attributes(), data.Properties, data.Measurements)
	}

	return data
}

func getResponseOrResultCode(attributes pdata.Map, attributeKey string) string {
	if codeAttribute, ok := attributes.Get(attributeKey); ok {
		switch codeAttribute.Type() {
		case pdata.ValueTypeString:
			return codeAttribute.StringVal()
		case pdata.ValueTypeInt:
			return strconv.FormatInt(codeAttribute.IntVal(), 10)
		}
	}
	return ""
}

func getSuccessFromAttributes(attributes pdata.Map) (bool, error) {
	if responseCodeAttribute, ok := attributes.Get(successAttribute); ok {
		switch responseCodeAttribute.Type() {
		case pdata.ValueTypeBool:
			return responseCodeAttribute.BoolVal(), nil
		case pdata.ValueTypeString:
			success, err := strconv.ParseBool(responseCodeAttribute.StringVal())
			if err != nil {
				return success, err
			}
			return success, nil
		}
	}
	return false, errNoSuccessAttrAvailable
}

func newLogPacker(logger *zap.Logger) *logPacker {
	packer := &logPacker{
		logger: logger,
	}
	return packer
}
