## FusionAuth .NET Core Client
![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)

If you're integrating FusionAuth with a .NET Core application, this library will speed up your development time.

Here's a small Example showing how to use this client: [Example.cs](https://github.com/FusionAuth/fusionauth-netcore-client/blob/master/fusionauth-netcore-client-test/fusionauth-netcore-client-test/test/io/fusionauth/Example.cs)

For additional information and documentation on FusionAuth refer to [https://fusionauth.io](https://fusionauth.io).

https://www.nuget.org/packages/FusionAuth.Client/

Refer to the FusionAuth API documentation for request and response formats.
* https://fusionauth.io/docs/v1/tech/apis/
* https://fusionauth.io/docs/v1/tech/client-libraries/netcore

## Supported Frameworks
* .NET Standard 2.0, 2.1
* .NET Core 2.1, 3.1
* .NET 5
* .NET 6
* .NET 7 (tested with rc.1)

## Tests

There are some tests. Most require a running FusionAuth instance.

To run them: 

* `cd fusionauth-netcore-client-test/fusionauth-netcore-client-test`
* `dotnet build && dotnet test` # or, to run only a few
* `dotnet build && dotnet test --filter CorrectlyD`

## Questions and support

If you have a question or support issue regarding this client library, we'd love to hear from you.

If you have a paid edition with support included, please [open a ticket in your account portal](https://account.fusionauth.io/account/support/). Learn more about [paid editions here](https://fusionauth.io/pricing).

Otherwise, please [post your question in the community forum](https://fusionauth.io/community/forum/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/FusionAuth/fusionauth-netcore-client.

If you find an issue with syntax, etc - this is likely a bug in the template. Feel free to submit a PR against the Client Builder project.
- [Client Builder](https://github.com/FusionAuth/fusionauth-client-builder)
- [netcore.client.interface.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/netcore.client.interface.ftl)
- [netcore.client.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/netcore.client.ftl)
- [netcore.client.sync.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/netcore.client.sync.ftl)
- [netcore.domain.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/netcore.domain.ftl)


## License

The code is available as open source under the terms of the [Apache v2.0 License](https://opensource.org/licenses/Apache-2.0).

