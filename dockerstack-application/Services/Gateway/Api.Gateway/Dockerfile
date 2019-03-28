FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app


FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY ["dockerstack-application/Services/Gateway/Api.Gateway/Api.Gateway.csproj", "dockerstack-application/Services/Gateway/Api.Gateway/"]
RUN dotnet restore "dockerstack-application/Services/Gateway/Api.Gateway/Api.Gateway.csproj"
COPY . .
WORKDIR "/src/dockerstack-application/Services/Gateway/Api.Gateway"
RUN dotnet build "Api.Gateway.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "Api.Gateway.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Api.Gateway.dll"]