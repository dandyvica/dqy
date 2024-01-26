-- a lua script to mimic dig output

-- all RRs field names
require 'rdata'

function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k, v in pairs(o) do
            if type(k) ~= 'number' then k = '"' .. k .. '"' end
            s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

-- display flags if they are set
local function bitlags(flags)
    local s = ""
    if flags.authorative_answer then
        s = s .. "aa "
    end
    if flags.truncation then
        s = s .. "tc "
    end
    if flags.recursion_desired then
        s = s .. "rd "
    end
    if flags.recursion_available then
        s = s .. "ra "
    end
    if flags.authentic_data then
        s = s .. "ad "
    end
    if flags.checking_disabled then
        s = s .. "cd "
    end

    return s
end

-- dump query
local function dump_query(query, resp)
    print(";; Got answer:")
    print(
        string.format(";; ->>HEADER<<- opcode: %s, status: %s, id: %d",
            string.upper(query.header.flags.op_code),
            string.upper(query.header.flags.response_code),
            query.header.id
        )
    )
    print(
        string.format(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d",
            bitlags(resp.header.flags),
            resp.header.qd_count,
            resp.header.an_count,
            resp.header.ns_count,
            resp.header.ar_count
        )
    )

    print("\n;; QUESTION SECTION:")
    print(
        string.format(";%s     %s        %s",
            query.question.qname,
            query.question.qtype,
            query.question.qclass
        )
    )
end

-- dump response
local function dump_response(resp)
    -- ANSWER section depends on ns_count
    print("\n;; ANSWER SECTION:")

    for i = 1, resp.header.an_count do
        print(
            string.format("%s         %d       %s       %s     %s",
                resp.answer[i].name,
                resp.answer[i].ttl,
                resp.answer[i].class,
                resp.answer[i].type,
                RData.format(resp.answer[i].type, resp.answer[i].rdata)
            )
        )
    end

    -- AUTHORITY section depends on ns_count
    print("\n;; AUTHORITY SECTION:")

    for i = 1, resp.header.ns_count do
        print(
            string.format("%s         %d       %s       %s     %s",
                resp.authority[1].name,
                resp.authority[1].ttl,
                resp.authority[1].class,
                resp.authority[1].type,
                RData.format(resp.authority[1].type, resp.authority[1].rdata)
            )
        )
    end
end

-- dump info structure
local function dump_info(i)
    print(string.format("\n;; Query time: %d", i.elapsed))
    print(string.format(";; SERVER: %s (%s)", i.endpoint, i.mode))
    print(string.format(";; MSG SIZE  rcvd: %d", i.bytes_received))
end

-- only 1 answer
dump_query(dns[1].query, dns[1].response)
dump_response(dns[1].response)
dump_info(info)
