package output

import (
	"compress/gzip"
	"io"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/google/pprof/proto"
)

type Writer struct {
	Out      *pb.Profile
	destName string
}

func NewWriter(dstName string, sampleTypes ...string) *Writer {
	return &Writer{
		destName: dstName,
		Out: &pb.Profile{
			SampleType: sampleTypes,
		},
	}
}

func (w *Writer) AddSample(sample *pb.Sample) {
	w.Out.Samples = append(w.Out.Samples, sample)
}

func (w *Writer) AddMapping(mapping *pb.Mapping) {
	w.Out.Mappings = append(w.Out.Mappings, mapping)
}

func (w *Writer) AddLocation(location *pb.Location) {
	w.Out.Locations = append(w.Out.Locations, location)
}

func (w *Writer) AddFunction(function *pb.Function) {
	w.Out.Function = append(w.Out.Function)
}

func (w *Writer) SetTime(t time.Time) {
	w.Out.TimesNanos = t.UnixNano()
}

func (w *Writer) SetDuration(d time.Duration) {
	w.Out.DurationNanos = d.Nanoseconds()
}

func (w *Writer) SetNumEvents(num int64) {
	w.Out.Period = num
}

func (w *Writer) WriteTo(dest io.Writer) (n int, err error) {
	gzipWriter := gzip.NewWriter(dest)
	payload, err := proto.Marshal(w.Out)
	if err != nil {
		return 0, err
	}
	return gzipWriter.Writer(payload)
}

func (w *Writer) Output() (err error) {
	var writer io.Writer
	if len(w.destName) == 0 {
		writer = os.Stdout
	} else {
		writer, err = os.Open(w.destName)
		if err != nil {
			return err
		}
	}
	_, err = w.WriteTo(writer)
	if err != nil {
		return err
	}
	return nil
}
