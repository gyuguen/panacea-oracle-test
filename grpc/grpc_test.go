package grpc_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb"
	datadeal "github.com/medibloc/panacea-oracle/pb/datadeal/v0"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Res struct {
	req time.Time
	res time.Time
	*datadeal.ValidateDataResponse
	error
}

func TestGrpcConnection(t *testing.T) {

	ctx := context.Background()
	conn, err := grpc.DialContext(
		ctx,
		"20.24.34.167:8085",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cli := datadeal.NewDataDealServiceClient(conn)

	encryptedData := `
	{
	  "provider_address": "panacea19rj4fc86r5d7jwslfjwqpvq8zzk06cu38krge0",
	  "data_hash": "13341f91f0da76d2adb67b519e2c9759822ceafd193bd26435ba0d5eee4c3a2b",
	  "encrypted_data": "TfH9MWV6wUJIAy3eo5tWwjygDBvUmeQe6wjNDPu/uvsud+cYYAAmWJtRevzshI1ilCTNlVMy86hIcLRYsevMtqYwKKloR1PZA6Eiy+bXPaiu39+8xRW8l9JDjrsTzTWgyAWeoQPSOnbcuz7OoRd90fQzLt4chpK5TrMEfzTy7FDFDXaT5rmXtUx0Xj/BAdsP8ZcOxekHhJThHFm7siU=",
	  "deal_id": 1
	}
	`

	r := strings.NewReader(encryptedData)
	req := &datadeal.ValidateDataRequest{}
	jsonpb.Unmarshal(r, req)

	jwtToken := "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3ODM2Njc0NDMsImlhdCI6MTY3NTY2NzQ0MywiaXNzIjoicGFuYWNlYTE5cmo0ZmM4NnI1ZDdqd3NsZmp3cXB2cTh6emswNmN1MzhrcmdlMCIsIm5iZiI6MTY3NTY2NzQ0M30.01F7wXAX1K0Yi_b5GwSKo4KrhiLnsrYh4YtsvfREFlzwbhgoaaN0xlX1cc5WzV0dtZkOSgXo4I42D5nvZn-lvw"
	md := metadata.Pairs(
		"Authorization", fmt.Sprintf("Bearer %s", jwtToken),
	)

	resList := make([]Res, 0)

	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx = metadata.NewOutgoingContext(context.Background(), md)
			reqTime := time.Now()
			res, err := cli.ValidateData(ctx, req)
			resTime := time.Now()
			resList = append(resList, Res{
				ValidateDataResponse: res,
				error:                err,
				req:                  reqTime,
				res:                  resTime,
			})
		}()
	}

	wg.Wait()

	sort.SliceStable(resList, func(i, j int) bool {
		return resList[i].req.Before(resList[j].req)
	})

	for _, res := range resList {
		log.Infof("req: %s, res: %s, respond: %s, err: %v", res.req.Format(time.StampNano), res.res.Format(time.StampNano), res.ValidateDataResponse, res.error)
	}
}
