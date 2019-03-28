FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY ../../../MyMicroservicesApplication.sln ./MyMicroservicesApplication.sln
COPY ./NuGet.Config ./
COPY ["../AuthService/AuthService.csproj", "dockerstack-application/Services/AuthService/"]
RUN dotnet restore "dockerstack-application/Services/AuthService/AuthService.csproj"
COPY . .
WORKDIR "/src/dockerstack-application/Services/AuthService"
RUN dotnet build "AuthService.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "AuthService.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "AuthService.dll"]