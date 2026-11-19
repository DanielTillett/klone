#include <klin/io.h>
#include <klin/response.h>

void wa_test(response_t *response);

void wa_test(response_t *response) 
{
    io_printf(response_io(response), "Custom Web Application");
}
