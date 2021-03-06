FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY ["dockerstack-application/Services/Basket/Basket.Application/Basket.Application.csproj", "dockerstack-application/Services/Basket/Basket.Application/"]
COPY ["dockerstack-application/EcosystemBlocks/EventBus/EventBusAwsSns/EventBusAwsSns.csproj", "dockerstack-application/EcosystemBlocks/EventBus/EventBusAwsSns/"]
COPY ["dockerstack-application/EcosystemBlocks/EventBus/EventBus/EventBus.csproj", "dockerstack-application/EcosystemBlocks/EventBus/EventBus/"]
COPY ["dockerstack-application/EcosystemBlocks/IntegrationEventsContext/IntegrationEventsContext/IntegrationEventsContext.csproj", "dockerstack-application/EcosystemBlocks/IntegrationEventsContext/IntegrationEventsContext/"]
RUN dotnet restore "dockerstack-application/Services/Basket/Basket.Application/Basket.Application.csproj"
COPY . .
WORKDIR "/src/dockerstack-application/Services/Basket/Basket.Application"
RUN dotnet build "Basket.Application.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "Basket.Application.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Basket.Application.dll"]