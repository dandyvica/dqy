-- mimic the dog tool output

-- all RRs field names
require 'rdata'

-- convert TTL to human format
local function to_hhmmss(seconds)
    seconds = seconds % (24 * 3600)
    local hours = seconds // 3600
    seconds = seconds % 3600
    local minutes = seconds // 60
    seconds = seconds % 60

    return string.format("%dh%2.2dm%2.2ds", hours, minutes, seconds)
end

-- just loop trough answers
for i, msg in ipairs(dns) do
    for j = 1, msg.response.header.an_count do
        print(
            string.format("%10.10s %-20.20s%s %-10.11s %-s",
                msg.response.answer[j].type,
                msg.response.answer[j].name,
                to_hhmmss(msg.response.answer[j].ttl),
                msg.response.answer[j].class,
                RData.format(msg.response.answer[j].type, msg.response.answer[j].rdata)
            )
        )
    end
end

