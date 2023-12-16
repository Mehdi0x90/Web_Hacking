# Unsafe Consumption of APIs (API10:2023)
Due to the above vulnerability, the attacker is able to send or receive information from the sources of the supply chain or implement her desired requests in a specific group.

* Example

GET request to receive weather information from a third-party service:

```html
GET /api/weather?location=New+York
```

### Non-compliant code (.NET)

```c#
[ApiController]
[Route("api/weather")]
public class WeatherController : ControllerBase
{
    private readonly IWeatherService weatherService;
    public WeatherController(IWeatherService weatherService)
    {
        this.weatherService = weatherService;
    }

    // GET /api/weather
    [HttpGet]
    public IActionResult GetWeather(string location)
    {
        // Make a direct call to the third-party weather API
        WeatherData weatherData =
        weatherService.GetWeatherData(location);

        return Ok(weatherData);
    }
    
    // Other methods...
}
```

### Compliant code (.NET)

```c#
[ApiController]
[Route("api/weather")]
public class WeatherController : ControllerBase
{
    private readonly IWeatherService weatherService;
    public WeatherController(IWeatherService weatherService)
    {
        this.weatherService = weatherService;
    }

    // GET /api/weather
    [HttpGet]
    public IActionResult GetWeather(string location)
    {
        // Validate the location parameter and restrict access to trusted sources
        if (!IsValidLocation(location))
        {
         return BadRequest();
        }

        // Make a call to the third-party weather API through the weather service
        WeatherData weatherData = weatherService.GetWeatherData(location);

        if (weatherData == null)
        {
            return NotFound();
        }
        return Ok(weatherData);
    }
    private bool IsValidLocation(string location)
    {
        // Implement validation logic to ensure the location is safe and trusted

        // This could involve white-listing trusted sources or validating against a known set of safe locations

        // Return true if the location is valid, false otherwise
        // Example: return Regex.IsMatch(location, "^[a-zA-Z]+(,[a-zA-Z]+)*$");

        // Implement your validation logic here
        // For simplicity, assuming any location is valid
        return true;
    }

    // Other methods...
}
```

## General prevention suggestions:

* Trust data received from external APIs with caution and rigorous validation.

* Check and verify the security and standards of the third-party service before connecting to it.

* Using encryption to communicate with external services and prevent sending sensitive information normally.

* Limiting access and levels allowed to third-party services and setting appropriate limits.

* Implementing protection mechanisms such as prototyping and generalization to ensure the security and reliability of data received from external services.

* Continuous monitoring and monitoring to detect and fix any defects in the security of external services.

* Training developers about security principles and correct use of external APIs.





















































































