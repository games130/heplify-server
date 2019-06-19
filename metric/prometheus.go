package metric

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"regexp"
	"time"
	"strconv"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify-server/config"
	"github.com/sipcapture/heplify-server/decoder"
	//"github.com/coocood/freecache"
	"github.com/muesli/cache2go"
	"github.com/mediocregopher/radix/v3"
	"github.com/hazelcast/hazelcast-go-client"
	//"github.com/hazelcast/hazelcast-go-client/core/aggregator"
	
)

const (
	invite    = "INVITE"
	register  = "REGISTER"
	cacheSize = 60 * 1024 * 1024
)

type Prometheus struct {
	TargetEmpty bool
	TargetIP    []string
	TargetName  []string
	TargetMap   map[string]string
	TargetConf  *sync.RWMutex
	cache       *fastcache.Cache
	RedisPool	*radix.Pool
	//CacheIMS         *freecache.Cache
	//CacheIMSReg		 *freecache.Cache
	hazelClient	hazelcast.Client
}

func (p *Prometheus) setup() (err error) {
	//default connected will be DB 0
	p.RedisPool,err = radix.NewPool("tcp","localhost:6379",10)
	if err != nil {
			logp.Err("RedisPool: %v", err)
	} else {
		logp.Info("RedisPool Connected")
	}
	
	// this is a ConnFunc which will set up a connection
	// and has a 1 minute timeout on all operations
	//OnlineConnFunc := func(network, addr string) (radix.Conn, error) {
	//	return radix.Dial(network, addr,
	//		radix.DialTimeout(1 * time.Minute),
	//		radix.DialSelectDB(1),
	//	)
	//}
	
	//OnlinePool,err = radix.NewPool("tcp","localhost:6379",10, PoolConnFunc(OnlineConnFunc))
	//if err != nil {
	//		logp.Err("OnlinePool: %v", err)
	//} else {
	//	logp.Info("OnlinePool Connected")
	//}
	
	
	//connection to hazelcast
	hazelConfig := hazelcast.NewConfig() // We create a config for illustrative purposes.
                                    // We do not adjust this config. Therefore it has default settings.
									// config.NetworkConfig().AddAddress("172.17.0.3:5701")
	p.hazelClient, err = hazelcast.NewClientWithConfig(hazelConfig)
	if err != nil {
		logp.Info("hazel error: ", err)
		return
	}
	logp.Info("connection: ", p.hazelClient.Name()) // Connects and prints the name of the client

	p.TargetConf = new(sync.RWMutex)
	p.TargetIP = strings.Split(cutSpace(config.Setting.PromTargetIP), ",")
	p.TargetName = strings.Split(cutSpace(config.Setting.PromTargetName), ",")
	p.cache = fastcache.New(cacheSize)
	
	//new
	//p.CacheIMS = freecache.NewCache(80 * 1024 * 1024)
	//p.CacheIMSReg = freecache.NewCache(80 * 1024 * 1024)
	
	//new
	if p.TargetIP[0] != "" && p.TargetName[0] != "" {
		for _, tn := range p.TargetName {
			if strings.HasPrefix(tn, "mp") {
				//mp = call only
				tnNew := strings.TrimPrefix(tn, "mp")
				prepopulateSIPCallError(tnNew)
			} else if strings.HasPrefix(tn, "mr") {
				//mr = call and register
				tnNew := strings.TrimPrefix(tn, "mr")
				prepopulateSIPCallError(tnNew)
				prepopulateSIPREGError(tnNew)
			} else if strings.HasPrefix(tn, "mv") {
				//mv = SIP register only
				tnNew := strings.TrimPrefix(tn, "mv")
				prepopulateSIPREGError(tnNew)
			}
		}
	}

	if len(p.TargetIP) == len(p.TargetName) && p.TargetIP != nil && p.TargetName != nil {
		if len(p.TargetIP[0]) == 0 || len(p.TargetName[0]) == 0 {
			logp.Info("expose metrics without or unbalanced targets")
			p.TargetIP[0] = ""
			p.TargetName[0] = ""
			p.TargetEmpty = true
		} else {
			for i := range p.TargetName {
				logp.Info("prometheus tag assignment %d: %s -> %s", i+1, p.TargetIP[i], p.TargetName[i])
			}
			p.TargetMap = make(map[string]string)
			for i := 0; i < len(p.TargetName); i++ {
				p.TargetMap[p.TargetIP[i]] = p.TargetName[i]
			}
		}
	} else {
		logp.Info("please give every PromTargetIP a unique IP and PromTargetName a unique name")
		return fmt.Errorf("faulty PromTargetIP or PromTargetName")
	}

	return err
}

func (p *Prometheus) expose(hCh chan *decoder.HEP) {
	for pkt := range hCh {
		packetsByType.WithLabelValues(pkt.NodeName, pkt.ProtoString).Inc()
		packetsBySize.WithLabelValues(pkt.NodeName, pkt.ProtoString).Set(float64(len(pkt.Payload)))

		var st, dt string
		if pkt.SIP != nil && pkt.ProtoType == 1 {
			if !p.TargetEmpty {
				p.checkTargetPrefix(pkt)
			}

			skip := false
			if dt == "" && st == "" && !p.TargetEmpty {
				skip = true
			}

			if !skip && ((pkt.SIP.FirstMethod == invite && pkt.SIP.CseqMethod == invite) ||
				(pkt.SIP.FirstMethod == register && pkt.SIP.CseqMethod == register)) {
				ptn := pkt.Timestamp.UnixNano()
				ik := []byte(pkt.CID)
				buf := p.cache.Get(nil, ik)
				if buf == nil || buf != nil && (uint64(ptn) < binary.BigEndian.Uint64(buf)) {
					sk := []byte(pkt.SrcIP + pkt.CID)
					tb := make([]byte, 8)

					binary.BigEndian.PutUint64(tb, uint64(ptn))
					p.cache.Set(ik, tb)
					p.cache.Set(sk, tb)
				}
			}

			if !skip && ((pkt.SIP.CseqMethod == invite || pkt.SIP.CseqMethod == register) &&
				(pkt.SIP.FirstMethod == "180" || pkt.SIP.FirstMethod == "183" || pkt.SIP.FirstMethod == "200")) {
				ptn := pkt.Timestamp.UnixNano()
				did := []byte(pkt.DstIP + pkt.CID)
				if buf := p.cache.Get(nil, did); buf != nil {
					d := uint64(ptn) - binary.BigEndian.Uint64(buf)

					if dt == "" {
						dt = st
					}

					if pkt.SIP.CseqMethod == invite {
						srd.WithLabelValues(dt, pkt.NodeName).Set(float64(d))
					} else {
						rrd.WithLabelValues(dt, pkt.NodeName).Set(float64(d))
						p.cache.Del([]byte(pkt.CID))
					}
					p.cache.Del(did)
				}
			}

			if p.TargetEmpty {
				k := []byte(pkt.CID + pkt.SIP.FirstMethod + pkt.SIP.CseqMethod)
				if p.cache.Has(k) {
					continue
				}
				p.cache.Set(k, nil)
				methodResponses.WithLabelValues("", "", pkt.NodeName, pkt.SIP.FirstMethod, pkt.SIP.CseqMethod).Inc()

				if pkt.SIP.ReasonVal != "" && strings.Contains(pkt.SIP.ReasonVal, "850") {
					reasonCause.WithLabelValues(st, extractXR("cause=", pkt.SIP.ReasonVal), pkt.SIP.FirstMethod).Inc()
				}
			}

			if pkt.SIP.RTPStatVal != "" {
				p.dissectXRTPStats(st, pkt.SIP.RTPStatVal)
			}

		} else if pkt.ProtoType == 5 {
			p.dissectRTCPStats(pkt.NodeName, []byte(pkt.Payload))
		} else if pkt.ProtoType == 34 {
			p.dissectRTPStats(pkt.NodeName, []byte(pkt.Payload))
		} else if pkt.ProtoType == 35 {
			p.dissectRTCPXRStats(pkt.NodeName, pkt.Payload)
		} else if pkt.ProtoType == 38 {
			p.dissectHoraclifixStats([]byte(pkt.Payload))
		} else if pkt.ProtoType == 112 {
			logAlert.WithLabelValues(pkt.NodeName, pkt.CID, pkt.HostTag).Inc()
		}
	}
}









//new
func (p *Prometheus) checkTargetPrefix(pkt *decoder.HEP) {
	st, sOk := p.TargetMap[pkt.SrcIP]
	if sOk {
		firstTwoChar := st[:2]
		tnNew := st[2:]
		
		heplify_SIP_capture_all.WithLabelValues(tnNew, pkt.SIP.FirstMethod, pkt.SrcIP, pkt.DstIP).Inc()
		methodResponses.WithLabelValues(tnNew, "src", "1", pkt.SIP.FirstMethod, pkt.SIP.CseqMethod).Inc()
		if pkt.SIP.RTPStatVal != "" {
			p.dissectXRTPStats(tnNew, pkt.SIP.RTPStatVal)
		}
		
		switch firstTwoChar {
			case "mo":
				//for now do nothing as the above already done it
			case "mp":
				p.ownPerformance(pkt, tnNew, pkt.DstIP)
			case "mr":
				p.ownPerformance(pkt, tnNew, pkt.DstIP)
				p.regPerformance(pkt, tnNew)
			case "mv":
				p.regPerformance(pkt, tnNew)
			default:
				logp.Err("improper prefix %v with ip %v", st, pkt.SrcIP)
		}
		
		if pkt.SIP.ReasonVal != "" && strings.Contains(pkt.SIP.ReasonVal, "850") {
			reasonCause.WithLabelValues(tnNew, extractXR("cause=", pkt.SIP.ReasonVal), pkt.SIP.FirstMethod).Inc()
		}
	}
	
	dt, dOk := p.TargetMap[pkt.DstIP]
	if dOk {
		firstTwoChar := dt[:2]
		tnNew := dt[2:]
		
		heplify_SIP_capture_all.WithLabelValues(tnNew, pkt.SIP.FirstMethod, pkt.SrcIP, pkt.DstIP).Inc()
		methodResponses.WithLabelValues(tnNew, "dst", "1", pkt.SIP.FirstMethod, pkt.SIP.CseqMethod).Inc()
		
		switch firstTwoChar {
			case "mo":
				//for now do nothing as the above already done it
			case "mp":
				p.ownPerformance(pkt, tnNew, pkt.SrcIP)
			case "mr":
				p.ownPerformance(pkt, tnNew, pkt.SrcIP)
				p.regPerformance(pkt, tnNew)
			case "mv":
				p.regPerformance(pkt, tnNew)
			default:
				logp.Err("improper prefix %v with ip %v", st, pkt.DstIP)
		}
	}
}

	
func (p *Prometheus) ownPerformance(pkt *decoder.HEP, tnNew string, peerIP string) {
	var value string
	var errorSIP = regexp.MustCompile(`[456]..`)
	keyCallID1 := "IMS_CallID:"+tnNew+pkt.SIP.CallID
	LongTimer := "43200"
	
	if pkt.SIP.FirstMethod == "INVITE" {
		//logp.Info("SIP INVITE message callid: %v", pkt.SIP.CallID)
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyCallID1))
		//_, err := p.CacheIMS.Get([]byte(tnNew+pkt.SIP.CallID))
		if value == "" {
			_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyCallID1, LongTimer, "INVITE"))
			//_ = p.CacheIMS.Set([]byte(tnNew+pkt.SIP.CallID), []byte("INVITE"), 43200)
			heplify_SIP_perf_raw.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, "SC.AttSession").Inc()
			//logp.Info("%v----> INVITE message added to cache", tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.CallID)
		}
	} else if pkt.SIP.FirstMethod == "CANCEL" {
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyCallID1))
		//value,err := p.CacheIMS.Get([]byte(tnNew+pkt.SIP.CallID))
		if value != "" {
			if value == "INVITE"{
				_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyCallID1))
				//_ = p.CacheIMS.Del([]byte(tnNew+pkt.SIP.CallID))
				heplify_SIP_perf_raw.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, "SC.RelBeforeRing").Inc()
			} else {
				logp.Warn("Line 289")
			}
		}
	} else if pkt.SIP.FirstMethod == "BYE" {
		//check if the call has been answer or not. If not answer then dont need to update just delete the cache.
		//if dont have this check will cause AccumulatedCallDuration to be very big because start time is 0.
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyCallID1))
		//value, err := p.CacheIMS.Get([]byte(tnNew+pkt.SIP.CallID))
		if value != "" {
			_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyCallID1))
			//_ = p.CacheIMS.Del([]byte(tnNew+pkt.SIP.CallID))
			if value == "ANSWERED" {
				//new
				cache2goGot, err2 := cache2go.Cache(tnNew+peerIP).Value(pkt.SIP.CallID)
				if err2 != nil {
					logp.Info("ERROR BYE but no start time")
					logp.Info("END OF CALL,node,%v,from,%v,to,%v,callid,%v", tnNew, pkt.SIP.FromUser, pkt.SIP.ToUser, pkt.SIP.CallID)
				} else {
					PreviousUnixTimestamp := cache2goGot.Data().(int64)
					CurrentUnixTimestamp := time.Now().Unix()
					cache2go.Cache(tnNew+peerIP).Delete(pkt.SIP.CallID)
					heplify_SIP_perf_raw.WithLabelValues(tnNew, "1", peerIP, "SC.OnlineSession").Set(float64(cache2go.Cache(tnNew+peerIP).Count()))
					heplify_SIP_perf_raw.WithLabelValues(tnNew, "1", peerIP, "SC.CallCounter").Inc()
					heplify_SIP_perf_raw.WithLabelValues(tnNew, "1", peerIP, "SC.AccumulatedCallDuration").Add(float64(CurrentUnixTimestamp-PreviousUnixTimestamp))
					logp.Info("END OF CALL,node,%v,from,%v,to,%v,callid,%v,start_timestamp,%v,end_timestamp,%v,difference,%v", tnNew, pkt.SIP.FromUser, pkt.SIP.ToUser, pkt.SIP.CallID, PreviousUnixTimestamp, CurrentUnixTimestamp, (CurrentUnixTimestamp-PreviousUnixTimestamp))
				}
			}
		} else {
			//logp.Warn("BYE not found tnNew:%v cid:%v",tnNew,pkt.SIP.CallID)
		}
	} else if pkt.SIP.CseqMethod == "INVITE" {
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyCallID1))
		//value, err := p.CacheIMS.Get([]byte(tnNew+pkt.SIP.CallID))
		if value != "" && value != "ANSWERED" {
			if value == "INVITE"{
				switch pkt.SIP.FirstMethod {
				case "180":
					_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyCallID1, LongTimer, "RINGING"))
					//err = p.CacheIMS.Set([]byte(tnNew+pkt.SIP.CallID), []byte("RINGING"), 43200)
					heplify_SIP_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "SC.SuccSession").Inc()
					//logp.Info("----> 180 RINGING found")
				case "200":
					_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyCallID1, LongTimer, "ANSWERED"))
					//err = p.CacheIMS.Set([]byte(tnNew+pkt.SIP.CallID), []byte("ANSWERED"), 43200)
					
					//new
					CurrentUnixTimestamp := time.Now().Unix()
					cache2go.Cache(tnNew+peerIP).Add(pkt.SIP.CallID, 43200*time.Second, CurrentUnixTimestamp)
					heplify_SIP_perf_raw.WithLabelValues(tnNew, "1", peerIP, "SC.OnlineSession").Set(float64(cache2go.Cache(tnNew+peerIP).Count()))
					heplify_SIP_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "SC.SuccSession").Inc()
					//logp.Info("----> 200 before ringing")
					//logp.Info("%v----> INVITE answered", tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.CallID)
				case "486", "600", "404", "484":
					//found some miscalculation because of user already ringing but later reject the call. INVITE sent, 180 receive and after a while 486 receive due to reject of call.
					//because of this 180 counted as SC.SuccSession then 486 counted as SC.FailSessionUser, this cause NER to be calculated wrongly
					_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyCallID1))
					//_ = p.CacheIMS.Del([]byte(tnNew+pkt.SIP.CallID))
					heplify_SIP_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "SC.FailSessionUser").Inc()
					heplify_SIPCallErrorResponse.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, pkt.SIP.FirstMethod).Inc()
				default:
					if errorSIP.MatchString(pkt.SIP.FirstMethod){
						_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyCallID1))
						//_ = p.CacheIMS.Del([]byte(tnNew+pkt.SIP.CallID))
						heplify_SIPCallErrorResponse.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, pkt.SIP.FirstMethod).Inc()
					}
				}
			} else if pkt.SIP.FirstMethod == "200" && value == "RINGING" {
				_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyCallID1, LongTimer, "ANSWERED"))
				//err = p.CacheIMS.Set([]byte(tnNew+pkt.SIP.CallID), []byte("ANSWERED"), 43200)
				
				//new
				CurrentUnixTimestamp := time.Now().Unix()
				cache2go.Cache(tnNew+peerIP).Add(pkt.SIP.CallID, 43200*time.Second, CurrentUnixTimestamp)
				heplify_SIP_perf_raw.WithLabelValues(tnNew, "1", peerIP, "SC.OnlineSession").Set(float64(cache2go.Cache(tnNew+peerIP).Count()))

				//logp.Info("%v----> INVITE answered", tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.CallID)
			}
		}
	}
}



func (p *Prometheus) regPerformance(pkt *decoder.HEP, tnNew string) {
	var value string
	var errorSIP = regexp.MustCompile(`[456]..`)
	SIPRegSessionTimer := "1800"
	SIPRegTryTimer := "180"
	keyRegForward := "IMSReg:"+tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.FromUser
	keyRegBackward := "IMSReg:"+tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser
	
	regMap, _ := p.hazelClient.GetMap("REG:"+tnNew)

	if pkt.SIP.FirstMethod == "REGISTER" {
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyRegForward))
		//value, err := p.CacheIMSReg.Get([]byte(tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.FromUser))
		
		if value == "" {
			//[]byte("0") means 1st time register
			_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyRegForward, SIPRegTryTimer, "0"))
			//_ = p.CacheIMSReg.Set([]byte(tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.FromUser), []byte("0"), SIPRegTryTimer)
			heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, "RG.1REGAttempt").Inc()
		} else if value == "2"{
			if pkt.SIP.Expires == "0" {
				//[]byte("3") means un-register
				logp.Info("%v is going to un-register. Expires=0", pkt.SIP.FromUser)
				_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyRegForward, SIPRegTryTimer, "3"))
				//_ = p.CacheIMSReg.Set([]byte(tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.FromUser), []byte("3"), SIPRegTryTimer)
				heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, "RG.UNREGAttempt").Inc()
				
				regMap.Delete(tnNew+pkt.SIP.FromUser)
				var count int32 
				count, _ = regMap.Size()
				//cache2go.Cache(tnNew).Delete(tnNew+pkt.SIP.FromUser)
				heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, "1", "1", "RG.RegisteredUsers").Set(float64(count))
				//heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, "1", "1", "RG.RegisteredUsers").Set(float64(cache2go.Cache(tnNew).Count()))
			} else {
				//[]byte("1") means re-register
				_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyRegForward, SIPRegTryTimer, "1"))
				//_ = p.CacheIMSReg.Set([]byte(tnNew+pkt.SrcIP+pkt.DstIP+pkt.SIP.FromUser), []byte("1"), SIPRegTryTimer)
				heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, "RG.RREGAttempt").Inc()
			}
		}		
	} else if pkt.SIP.CseqMethod == "REGISTER"{
		_ = p.RedisPool.Do(radix.Cmd(&value, "GET", keyRegBackward))
		//value, err := p.CacheIMSReg.Get([]byte(tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser))
		
		if value != "" {
			if pkt.SIP.FirstMethod == "200" {
				//logp.Info("hazelcast: add to hazelcast")
				regMap.SetWithTTL(tnNew+pkt.SIP.FromUser, "value", 1800*time.Second)
				var count int32 
				count, _ = regMap.Size()
				//cache2go.Cache(tnNew).Add(tnNew+pkt.SIP.FromUser, 1800*time.Second, nil)
				//logp.Info("hazelcast: add complete")
				
				heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, "1", "1", "RG.RegisteredUsers").Set(float64(count))
				//logp.Info("hazelcast: add to prometheus")
				//heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, "1", "1", "RG.RegisteredUsers").Set(float64(cache2go.Cache(tnNew).Count()))
				
				if value == "0"{
					heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "RG.1REGAttemptSuccess").Inc()
					//[]byte("2") means success register
					_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyRegBackward, SIPRegSessionTimer, "2"))
					//p.CacheIMSReg.Set([]byte(tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser), []byte("2"), SIPRegSessionTimer)
				} else if value == "1"{
					heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "RG.RREGAttemptSuccess").Inc()
					//[]byte("2") means success register
					_ = p.RedisPool.Do(radix.Cmd(nil, "SETEX", keyRegBackward, SIPRegSessionTimer, "2"))
					//p.CacheIMSReg.Set([]byte(tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser), []byte("2"), SIPRegSessionTimer)
				} else if value == "3"{
					heplify_SIP_REG_perf_raw.WithLabelValues(tnNew, pkt.DstIP, pkt.SrcIP, "RG.UNREGAttemptSuccess").Inc()
					_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyRegBackward))
					//_ = p.CacheIMSReg.Del([]byte(tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser))
				}
			} else if errorSIP.MatchString(pkt.SIP.FirstMethod){
				heplify_SIPRegisterErrorResponse.WithLabelValues(tnNew, pkt.SrcIP, pkt.DstIP, pkt.SIP.FirstMethod).Inc()
				switch pkt.SIP.FirstMethod {
				case "401", "423":
					//do nothing
				default:
					regMap.Delete(tnNew+pkt.SIP.FromUser)
					//cache2go.Cache(tnNew).Delete(tnNew+pkt.SIP.FromUser)
					_ = p.RedisPool.Do(radix.Cmd(nil, "DEL", keyRegBackward))
					//_ = p.CacheIMSReg.Del([]byte(tnNew+pkt.DstIP+pkt.SrcIP+pkt.SIP.FromUser))
				}
			}
		}
	}
}


func prepopulateSIPCallError(tnNew string) {
	for j := 400; j <= 699; j++ {
        heplify_SIPCallErrorResponse.WithLabelValues(tnNew, "1", "1", strconv.Itoa(j)).Set(0)
	}
}

func prepopulateSIPREGError(tnNew string) {
	for j := 400; j <= 699; j++ {
        heplify_SIPRegisterErrorResponse.WithLabelValues(tnNew, "1", "1", strconv.Itoa(j)).Set(0)
	}
}
