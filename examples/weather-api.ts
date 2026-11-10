/**
 * Weather API MCP Server Example
 *
 * A simulated weather service demonstrating:
 * - API-like data fetching
 * - Resources for city data
 * - Forecast generation
 */

import { z } from "zod";
import { mcp } from "@futurity/plugins";
import { exampleManifest, examplePort } from "./config";

const Failure = z.object({ error: z.string(), availableCities: z.array(z.string()).optional() });
const City = z.object({
	name: z.string(),
	country: z.string(),
	lat: z.number(),
	lon: z.number(),
	timezone: z.string(),
});
const Weather = z.object({
	temperature: z.object({ celsius: z.number(), fahrenheit: z.number() }),
	humidity: z.number(),
	windSpeed: z.object({ kmh: z.number(), mph: z.number() }),
	condition: z.string().optional(),
	precipitation: z.number(),
	uvIndex: z.number(),
});

// Simulated weather data
const cities: Record<
	string,
	{
		name: string;
		country: string;
		lat: number;
		lon: number;
		timezone: string;
	}
> = {
	nyc: { name: "New York", country: "US", lat: 40.7128, lon: -74.006, timezone: "America/New_York" },
	london: { name: "London", country: "UK", lat: 51.5074, lon: -0.1278, timezone: "Europe/London" },
	tokyo: { name: "Tokyo", country: "JP", lat: 35.6762, lon: 139.6503, timezone: "Asia/Tokyo" },
	paris: { name: "Paris", country: "FR", lat: 48.8566, lon: 2.3522, timezone: "Europe/Paris" },
	sydney: { name: "Sydney", country: "AU", lat: -33.8688, lon: 151.2093, timezone: "Australia/Sydney" },
	dubai: { name: "Dubai", country: "AE", lat: 25.2048, lon: 55.2708, timezone: "Asia/Dubai" },
	singapore: { name: "Singapore", country: "SG", lat: 1.3521, lon: 103.8198, timezone: "Asia/Singapore" },
	berlin: { name: "Berlin", country: "DE", lat: 52.52, lon: 13.405, timezone: "Europe/Berlin" },
};

const conditions = ["sunny", "cloudy", "partly cloudy", "rainy", "stormy", "snowy", "foggy", "windy"];

// Generate pseudo-random but consistent weather for a city/date
function getWeather(cityId: string, date: Date) {
	const city = cities[cityId];
	if (!city) return null;

	// Use city lat + date for pseudo-random but consistent values
	const seed = city.lat * 1000 + date.getDate() + date.getMonth() * 31;
	const rand = (offset: number) => Math.abs(Math.sin(seed + offset) * 10000) % 1;

	// Base temperature varies by latitude (colder near poles)
	const baseTemp = 25 - Math.abs(city.lat) * 0.5;
	// Seasonal variation (Northern hemisphere summer in July)
	const month = date.getMonth();
	const seasonalOffset = city.lat > 0 
		? Math.cos(((month - 6) / 12) * 2 * Math.PI) * 15
		: Math.cos(((month) / 12) * 2 * Math.PI) * 15;
	
	const temp = Math.round(baseTemp + seasonalOffset + (rand(1) - 0.5) * 10);
	const humidity = Math.round(40 + rand(2) * 50);
	const windSpeed = Math.round(5 + rand(3) * 25);
	const conditionIndex = Math.floor(rand(4) * conditions.length);
	const condition = conditions[conditionIndex];
	const precipitation = condition === "rainy" || condition === "stormy" ? Math.round(rand(5) * 20) : 0;

	return {
		temperature: { celsius: temp, fahrenheit: Math.round(temp * 9/5 + 32) },
		humidity,
		windSpeed: { kmh: windSpeed, mph: Math.round(windSpeed * 0.621) },
		condition,
		precipitation,
		uvIndex: Math.round(1 + rand(6) * 10),
	};
}

const app = mcp({
	manifest: exampleManifest("weather-api", "Weather API", "Simulated weather information"),
	futurity: false,
	instructions: `A weather information server.

Tools:
- get_current_weather: Get current weather for a city
- get_forecast: Get 7-day forecast
- search_cities: Search available cities
- compare_weather: Compare weather between cities

Resources:
- weather://cities - List of available cities
- weather://[city_id] - Current weather for a city`,
});

// Get current weather
app.tool("get_current_weather", {
	description: "Get current weather for a city",
	annotations: { readOnlyHint: true },
	input: z.object({
		city: z.string().describe("City ID (e.g., 'nyc', 'london', 'tokyo')"),
	}),
	output: z.union([z.object({ city: City, weather: Weather.nullable(), timestamp: z.string() }), Failure]),
	handler: async ({ city }) => {
		const cityId = city.toLowerCase();
		const cityData = cities[cityId];
		
		if (!cityData) {
			return { 
				error: "City not found",
				availableCities: Object.keys(cities),
			};
		}

		const weather = getWeather(cityId, new Date());
		return {
			city: cityData,
			weather,
			timestamp: new Date().toISOString(),
		};
	},
});

// Get forecast
app.tool("get_forecast", {
	description: "Get 7-day weather forecast",
	annotations: { readOnlyHint: true },
	input: z.object({
		city: z.string().describe("City ID"),
		days: z.number().min(1).max(14).default(7).describe("Number of days"),
	}),
	output: z.union([
		z.object({
			city: City,
			forecast: z.array(Weather.partial().extend({ date: z.string().optional(), dayOfWeek: z.string() })),
			generatedAt: z.string(),
		}),
		Failure,
	]),
	handler: async ({ city, days }) => {
		const cityId = city.toLowerCase();
		const cityData = cities[cityId];
		
		if (!cityData) {
			return { error: "City not found" };
		}

		const forecast = [];
		const today = new Date();
		
		for (let i = 0; i < days; i++) {
			const date = new Date(today);
			date.setDate(date.getDate() + i);
			
			const weather = getWeather(cityId, date);
			forecast.push({
				date: date.toISOString().split("T")[0],
				dayOfWeek: date.toLocaleDateString("en-US", { weekday: "long" }),
				...weather,
			});
		}

		return {
			city: cityData,
			forecast,
			generatedAt: new Date().toISOString(),
		};
	},
});

// Search cities
app.tool("search_cities", {
	description: "Search available cities",
	annotations: { readOnlyHint: true },
	input: z.object({
		query: z.string().optional().describe("Search query (optional)"),
		country: z.string().optional().describe("Filter by country code"),
	}),
	output: z.object({ cities: z.array(City.extend({ id: z.string() })), count: z.number() }),
	handler: async ({ query, country }) => {
		let results = Object.entries(cities);
		
		if (query) {
			const q = query.toLowerCase();
			results = results.filter(([id, city]) => 
				id.includes(q) || city.name.toLowerCase().includes(q)
			);
		}
		
		if (country) {
			const c = country.toUpperCase();
			results = results.filter(([_, city]) => city.country === c);
		}

		return {
			cities: results.map(([id, city]) => ({ id, ...city })),
			count: results.length,
		};
	},
});

// Compare weather
app.tool("compare_weather", {
	description: "Compare current weather between multiple cities",
	annotations: { readOnlyHint: true },
	input: z.object({
		cities: z.array(z.string()).min(2).max(5).describe("City IDs to compare"),
	}),
	output: z.object({
		comparison: z.array(Weather.partial().extend({ id: z.string(), city: z.string(), country: z.string() })),
		warmest: z.string().optional(),
		coldest: z.string().optional(),
		timestamp: z.string(),
	}),
	handler: async ({ cities: cityIds }) => {
		const comparison = [];
		
		for (const cityId of cityIds) {
			const id = cityId.toLowerCase();
			const cityData = cities[id];
			
			if (cityData) {
				const weather = getWeather(id, new Date());
				comparison.push({
					id,
					city: cityData.name,
					country: cityData.country,
					...weather,
				});
			}
		}

		// Sort by temperature
		comparison.sort((a, b) => (b.temperature?.celsius ?? 0) - (a.temperature?.celsius ?? 0));

		return {
			comparison,
			warmest: comparison[0]?.city,
			coldest: comparison[comparison.length - 1]?.city,
			timestamp: new Date().toISOString(),
		};
	},
});

// Get alerts (simulated)
app.tool("get_alerts", {
	description: "Get weather alerts for a city",
	annotations: { readOnlyHint: true },
	input: z.object({
		city: z.string().describe("City ID"),
	}),
	output: z.union([
		z.object({
			city: City,
			alerts: z.array(z.object({ type: z.string(), severity: z.string(), message: z.string() })),
			hasAlerts: z.boolean(),
			timestamp: z.string(),
		}),
		Failure,
	]),
	handler: async ({ city }) => {
		const cityId = city.toLowerCase();
		const cityData = cities[cityId];
		
		if (!cityData) {
			return { error: "City not found" };
		}

		const weather = getWeather(cityId, new Date());
		const alerts = [];

		if (weather!.temperature.celsius > 35) {
			alerts.push({
				type: "heat_warning",
				severity: "moderate",
				message: "High temperature warning - stay hydrated",
			});
		}
		if (weather!.temperature.celsius < 0) {
			alerts.push({
				type: "freeze_warning",
				severity: "moderate", 
				message: "Freezing temperatures expected",
			});
		}
		if (weather!.windSpeed.kmh > 50) {
			alerts.push({
				type: "wind_warning",
				severity: "moderate",
				message: "Strong winds expected",
			});
		}
		if (weather!.condition === "stormy") {
			alerts.push({
				type: "storm_warning",
				severity: "high",
				message: "Severe storm conditions possible",
			});
		}

		return {
			city: cityData,
			alerts,
			hasAlerts: alerts.length > 0,
			timestamp: new Date().toISOString(),
		};
	},
});

// Resources
app.resource("weather://cities", {
	description: "List of all available cities",
	fetch: async () => 
		Object.entries(cities).map(([id, city]) => ({ id, ...city })),
});

// Dynamic city resources
for (const [id, city] of Object.entries(cities)) {
	app.resource(`weather://${id}`, {
		description: `Current weather for ${city.name}`,
		fetch: async () => ({
			city,
			weather: getWeather(id, new Date()),
			timestamp: new Date().toISOString(),
		}),
	});
}

app.listen(examplePort);
console.log(`Weather API MCP server running on http://localhost:${examplePort}/mcp`);

