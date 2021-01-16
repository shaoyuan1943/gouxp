module github.com/shaoyuan1943/gouxp

go 1.13

require (
	github.com/fatih/color v1.9.0
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/klauspost/reedsolomon v1.9.9
	github.com/mmcloughlin/avo v0.0.0-20200803215136-443f81d77104 // indirect
	github.com/pkg/errors v0.9.1
	github.com/shaoyuan1943/gokcp v0.0.0-20201026071748-5b36d4c87f61
	github.com/valyala/fasthttp v1.16.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
	golang.org/x/tools v0.0.0-20200915031644-64986481280e // indirect
)

replace golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de => github.com/golang/crypto v0.0.0-20200728195943-123391ffb6de
