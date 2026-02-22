---
name: weather-check
description: Check current weather conditions and forecasts for any location.
version: 1.0.0
metadata:
  openclaw:
    emoji: "🌤️"
    requires:
      env:
        - OPENWEATHER_API_KEY
---

# Weather Check

## Overview

This skill allows you to check current weather conditions and get forecasts
for any city or location worldwide using the OpenWeatherMap API.

## Usage

### Current Weather
Ask for the current weather in any city:
- "What's the weather in Vienna?"
- "Is it raining in London?"
- "Temperature in Tokyo?"

### Forecast
Ask for upcoming weather:
- "What's the forecast for this weekend?"
- "Will it rain tomorrow in Berlin?"

## How It Works

The skill uses the OpenWeatherMap API:

```bash
curl "https://api.openweathermap.org/data/2.5/weather?q=${CITY}&appid=${OPENWEATHER_API_KEY}&units=metric"
```

## Response Format

Present weather data in a clean, readable format:
- Temperature (current, feels like, min/max)
- Conditions (sunny, cloudy, rainy, etc.)
- Humidity and wind speed
- Sunrise and sunset times

## Notes

- Requires a free API key from https://openweathermap.org
- Rate limited to 60 calls per minute on the free tier
- Temperatures are returned in Celsius by default
