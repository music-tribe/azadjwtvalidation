# Exponential Backoff

> NOTE: This is a fork from the excellent github.com/cenkalti/backoff. You really should be using that version.
>
> This fork was only made so we could modify v3 to make it compatible with running under [Yaegi](https://github.com/traefik/yaegi)
> in order to run a Traefik plugin we maintain: [azadjwtvalidation](https://github.com/music-tribe/azadjwtvalidation).

This is a Go port of the exponential backoff algorithm from [Google's HTTP Client Library for Java][google-http-java-client].

[Exponential backoff][exponential backoff wiki]
is an algorithm that uses feedback to multiplicatively decrease the rate of some process,
in order to gradually find an acceptable rate.
The retries exponentially increase and stop increasing when a certain threshold is met.

## Usage

Import path is `github.com/music-tribe/backoff/v3`. Please note the version part at the end.

godoc.org does not support modules yet,
so you can use https://godoc.org/gopkg.in/music-tribe/backoff.v3 to view the documentation.

## Contributing

You probably should be contributing to github.com/cenkalti/backoff
