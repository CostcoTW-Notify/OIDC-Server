#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["OIDC_Server/OIDC_Server.csproj", "OIDC_Server/"]
RUN dotnet restore "OIDC_Server/OIDC_Server.csproj"
COPY . .
WORKDIR "/src/OIDC_Server"
RUN dotnet build "OIDC_Server.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "OIDC_Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV run_in_container=true

ENTRYPOINT ["dotnet", "OIDC_Server.dll"]