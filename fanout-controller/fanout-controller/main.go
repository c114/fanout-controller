package main

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyNode struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Country  string `json:"country"`
	Source   string `json:"source"`
	Latency  time.Duration
}

type NodeProvider interface {
	Name() string
	FetchNodes(ctx context.Context) ([]ProxyNode, error)
}

type VPNGateProvider struct {
	MirrorURL string
}

func (v *VPNGateProvider) Name() string { return "vpngate" }

func (v *VPNGateProvider) FetchNodes(ctx context.Context) ([]ProxyNode, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", v.MirrorURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var nodes []ProxyNode
	for i, row := range records {
		if i == 0 || len(row) < 8 {
			continue
		}
		port, _ := strconv.Atoi(row[2])
		nodes = append(nodes, ProxyNode{
			IP:       row[1],
			Port:     port,
			Protocol: "openvpn",
			Country:  row[6],
			Source:   v.Name(),
		})
	}
	return nodes, nil
}

type GitHubListProvider struct {
	URLs []string
}

func (g *GitHubListProvider) Name() string { return "github-list" }

func (g *GitHubListProvider) FetchNodes(ctx context.Context) ([]ProxyNode, error) {
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})`)
	var nodes []ProxyNode
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, url := range g.URLs {
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			matches := re.FindAllStringSubmatch(string(body), -1)

			localNodes := make([]ProxyNode, 0, len(matches))
			for _, m := range matches {
				port, _ := strconv.Atoi(m[2])
				localNodes = append(localNodes, ProxyNode{
					IP:       m[1],
					Port:     port,
					Protocol: "socks5",
					Source:   g.Name(),
				})
			}

			mu.Lock()
			nodes = append(nodes, localNodes...)
			mu.Unlock()
		}(url)
	}

	wg.Wait()
	return nodes, nil
}

type CustomSubProvider struct {
	SubURL string
}

func (c *CustomSubProvider) Name() string { return "custom-sub" }

func (c *CustomSubProvider) FetchNodes(ctx context.Context) ([]ProxyNode, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.SubURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		decoded = body
	}

	lines := strings.Split(string(decoded), "\n")
	var nodes []ProxyNode
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "socks5://") {
			parts := strings.Split(strings.TrimPrefix(line, "socks5://"), ":")
			if len(parts) == 2 {
				port, _ := strconv.Atoi(parts[1])
				nodes = append(nodes, ProxyNode{
					IP:       parts[0],
					Port:     port,
					Protocol: "socks5",
					Source:   c.Name(),
				})
			}
		}
	}
	return nodes, nil
}

type NodePool struct {
	nodes []ProxyNode
	mu    sync.RWMutex
}

func (p *NodePool) Update(newNodes []ProxyNode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes = newNodes
	log.Printf("[NodePool] 已更新健康节点池，有效节点数: %d\n", len(p.nodes))
}

func (p *NodePool) GetRandom() (ProxyNode, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.nodes) == 0 {
		return ProxyNode{}, false
	}
	return p.nodes[time.Now().UnixNano()%int64(len(p.nodes))], true
}

func HealthCheck(nodes []ProxyNode, timeout time.Duration) []ProxyNode {
	var activeNodes []ProxyNode
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n ProxyNode) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", n.IP, n.Port), timeout)
			if err == nil {
				conn.Close()
				n.Latency = time.Since(start)
				mu.Lock()
				activeNodes = append(activeNodes, n)
				mu.Unlock()
			}
		}(node)
	}

	wg.Wait()
	return activeNodes
}

func startSocks5Server(listenAddr string, pool *NodePool) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("启动 SOCKS5 服务失败: %v", err)
	}
	log.Printf("[SOCKS5] 服务已在 %s 启动\n", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSocks5Conn(conn, pool)
	}
}

func handleSocks5Conn(clientConn net.Conn, pool *NodePool) {
	defer clientConn.Close()

	buf := make([]byte, 256)
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(clientConn, buf[:nmethods]); err != nil {
		return
	}
	clientConn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
		return
	}

	var destAddr string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
			return
		}
		destAddr = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return
		}
		addrLen := int(buf[0])
		if _, err := io.ReadFull(clientConn, buf[:addrLen]); err != nil {
			return
		}
		destAddr = string(buf[:addrLen])
	default:
		return
	}

	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	targetHost := fmt.Sprintf("%s:%d", destAddr, port)

	node, ok := pool.GetRandom()
	if !ok {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node.IP, node.Port), 5*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
	log.Printf("[Proxy] 转发流量 -> 目标: %s (经过节点: %s:%d)\n", targetHost, node.IP, node.Port)
}

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:1080", "SOCKS5 本地监听地址")
	interval := flag.Int("interval", 30, "节点刷新间隔 (分钟)")
	flag.Parse()

	pool := &NodePool{}

	providers := []NodeProvider{
		&VPNGateProvider{MirrorURL: "https://www.vpngate.net/api/iphone/"},
		&GitHubListProvider{
			URLs: []string{
				"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
				"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
				"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			},
		},
	}

	go func() {
		for {
			log.Println("[Manager] 开始从多源拉取节点...")
			var allNodes []ProxyNode
			var mu sync.Mutex
			var wg sync.WaitGroup

			for _, p := range providers {
				wg.Add(1)
				go func(provider NodeProvider) {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					nodes, err := provider.FetchNodes(ctx)
					if err != nil {
						log.Printf("[%s] 抓取失败: %v", provider.Name(), err)
						return
					}
					mu.Lock()
					allNodes = append(allNodes, nodes...)
					mu.Unlock()
					log.Printf("[%s] 获取原始节点: %d 个", provider.Name(), len(nodes))
				}(p)
			}
			wg.Wait()

			log.Printf("[Manager] 开始健康检测 (TCP Ping)...")
			activeNodes := HealthCheck(allNodes, 3*time.Second)
			pool.Update(activeNodes)

			time.Sleep(time.Duration(*interval) * time.Minute)
		}
	}()

	startSocks5Server(*listenAddr, pool)
}