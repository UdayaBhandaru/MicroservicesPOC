FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY ["dockerstack-application/Services/Orders/Orders.Application/Orders.Application.csproj", "dockerstack-application/Services/Orders/Orders.Application/"]
COPY ["dockerstack-application/EcosystemBlocks/EventBus/EventBusAwsSns/EventBusAwsSns.csproj", "dockerstack-application/EcosystemBlocks/EventBus/EventBusAwsSns/"]
COPY ["dockerstack-application/EcosystemBlocks/EventBus/EventBus/EventBus.csproj", "dockerstack-application/EcosystemBlocks/EventBus/EventBus/"]
COPY ["dockerstack-application/EcosystemBlocks/IntegrationEventsContext/IntegrationEventsContext/IntegrationEventsContext.csproj", "dockerstack-application/EcosystemBlocks/IntegrationEventsContext/IntegrationEventsContext/"]
COPY ["dockerstack-application/Services/Orders/Orders.Domain/Orders.Domain.csproj", "dockerstack-application/Services/Orders/Orders.Domain/"]
COPY ["dockerstack-application/Services/Orders/Orders.Infrastructure/Orders.Infrastructure.csproj", "dockerstack-application/Services/Orders/Orders.Infrastructure/"]
COPY ["dockerstack-application/EcosystemBlocks/WebHostCustomization/WebHost.Customization/WebHost.Customization.csproj", "dockerstack-application/EcosystemBlocks/WebHostCustomization/WebHost.Customization/"]
RUN dotnet restore "dockerstack-application/Services/Orders/Orders.Application/Orders.Application.csproj"
COPY . .
WORKDIR "/src/dockerstack-application/Services/Orders/Orders.Application"
RUN dotnet build "Orders.Application.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "Orders.Application.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Orders.Application.dll"]