module github.com/shaoyuan1943/gouxp

go 1.13

require (
	github.com/fatih/color v1.9.0
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/klauspost/reedsolomon v1.9.9
	github.com/mmcloughlin/avo v0.0.0-20200803215136-443f81d77104 // indirect
	github.com/pkg/errors v0.9.1
	github.com/shaoyuan1943/gokcp v0.0.0-20200915085911-94dab24b80d2
	github.com/valyala/fasthttp v1.16.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/sys v0.0.0-20200915084602-288bc346aa39 // indirect
	golang.org/x/tools v0.0.0-20200915031644-64986481280e // indirect
)

replace golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de => github.com/golang/crypto v0.0.0-20200728195943-123391ffb6de
