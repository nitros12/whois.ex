defmodule Whois.IndentRecord do
  @moduledoc """
  We want this to parse:

    Domain name:
        google.co.uk

    Data validation:
        Nominet was able to match the registrant's name and address against a 3rd party data source on 10-Dec-2012

    Registrar:
        Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]
        URL: http://www.markmonitor.com

    Relevant dates:
        Registered on: 14-Feb-1999
        Expiry date:  14-Feb-2019
        Last updated:  13-Jan-2018

  Into:

  %{
    "Domain name" => ["google.co.uk"],
    "Data Validation" => ["Nominet was able to match the registrant's name and address against a 3rd party data source on 10-Dec-2012"],
    "Registrar" => [
        "Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]",
        {"URL", "http://www.markmonitor.com"}
    ],
    "Relevant dates" => [
        {"Registered on", "14-Feb-1999"},
        {"Expiriy date", "14-Feb-2019"},
        {"Last updated", "13-Jan-2018"}
    ]
  }
  """

  defp leading_spaces_count(str) do
    ~r/^\s*/
    |> Regex.run(str)
    |> Enum.at(0)
    |> String.length()
  end

  # remove leading empty lines
  defp trim_empty_lines(lines) do
    Enum.filter(lines, & &1 != "")
  end

  defp split_on_indent_level(lines, level) do
    Enum.split_while(lines, & leading_spaces_count(&1) == level)
  end

  @doc """
  Parse indentation style whois response into a readable format.
  """
  def parse(lines, result \\ []) do
    trimmed = trim_empty_lines(lines)

    case parse_section(trimmed) do
      {:ok, section, remaining} ->
        parse(remaining, result ++ [section])

      :end ->
        Enum.into(result, %{})
    end
  end

  @header_regex ~r/(.+):/

  # parse a section, returning the parsed lines and the remaining lines
  # returns {:ok, {header, content}, remaining} on success
  # returns :end on end of parseable input
  defp parse_section([header | rest]) do
    header_indent = leading_spaces_count(header)

    header = header |> String.downcase |> String.trim

    [_, header] = Regex.run(@header_regex, header)

    content_indent = rest |> hd() |> leading_spaces_count()

    if content_indent <= header_indent do
      # assume we reached the end of parseable input
      :end
    else
      {content_lines, remaining_lines} = split_on_indent_level(rest, content_indent)

      content = Enum.map(content_lines, &parse_section_content_line/1)

      {:ok, {header, content}, remaining_lines}
    end
  end

  @content_line_regex ~r/(?<key>.+?):\s*(?<val>.+)/

  defp parse_section_content_line(line) do
    case Regex.named_captures(@content_line_regex, line) do
      %{"key" => key, "val" => val} ->
        key = key |> String.downcase |> String.trim
        val = String.trim(val)

        {key, val}

      nil ->
        String.trim(line)
    end
  end
end


defmodule Whois.Record do
  alias Whois.Contact

  defstruct [
    :domain,
    :raw,
    :nameservers,
    :registrar,
    :created_at,
    :updated_at,
    :expires_at,
    :contacts
  ]

  @type t :: %__MODULE__{
          domain: String.t(),
          raw: String.t(),
          nameservers: [String.t()],
          registrar: String.t(),
          created_at: NaiveDateTime.t(),
          updated_at: NaiveDateTime.t(),
          expires_at: NaiveDateTime.t(),
          contacts: %{
            registrant: Contact.t(),
            administrator: Contact.t(),
            technical: Contact.t()
          }
        }

  @doc """
  Parses the raw WHOIS server response in `raw` into a `%Whois.Record{}`.
  """
  @spec parse(String.t()) :: t
  def parse(raw) do
    record = %Whois.Record{
      raw: raw,
      nameservers: [],
      contacts: %{
        registrant: %Contact{},
        administrator: %Contact{},
        technical: %Contact{}
      }
    }

    record =
      raw
      |> String.replace("\r\n", "\n")
      |> String.split("\n")
      |> Enum.reduce(record, fn line, record ->
        line
        |> String.trim()
        |> String.split(":", parts: 2)
        |> case do
          [name, value] ->
            name = name |> String.trim() |> String.downcase()
            value = value |> String.trim()

            case name do
              "domain name" ->
                %{record | domain: value}

              "name server" ->
                %{record | nameservers: record.nameservers ++ [value]}

              "registrar" ->
                %{record | registrar: value}

              "sponsoring registrar" ->
                %{record | registrar: value}

              "creation date" ->
                %{record | created_at: parse_dt(value) || record.created_at}

              "updated date" ->
                %{record | updated_at: parse_dt(value) || record.updated_at}

              "expiration date" ->
                %{record | expires_at: parse_dt(value) || record.expires_at}

              "registry expiry date" ->
                %{record | expires_at: parse_dt(value) || record.expires_at}

              "registrant " <> name ->
                update_in(record.contacts.registrant, &parse_contact(&1, name, value))

              "admin " <> name ->
                update_in(record.contacts.administrator, &parse_contact(&1, name, value))

              "tech " <> name ->
                update_in(record.contacts.technical, &parse_contact(&1, name, value))

              _ ->
                record
            end

          _ ->
            record
        end
      end)

    nameservers =
      record.nameservers
      |> Enum.map(&String.downcase/1)
      |> Enum.uniq()

    %{record | nameservers: nameservers}
  end

  @nameserver_regex ~r/(?<domain>(\w|\d|\.)+)(\s*.+)?/

  # for parsing responses that use indentation and headers
  @doc """
  Parses the raw response with the indentation style parser.
  """
  @spec parse(String.t()) :: t
  def parse_indentation_style(raw) do
    record = %Whois.Record{
      raw: raw,
      nameservers: [],
      contacts: %{
        registrant: %Contact{},
        administrator: %Contact{},
        technical: %Contact{}
      }
    }

    record =
      raw
      |> String.replace("\r\n", "\n")
      |> String.split("\n")
      |> Whois.IndentRecord.parse()
      |> Enum.reduce(record, fn {k, v}, record ->
      case k do
        "domain" ->
          %{record | domain: v}

        "name servers" ->
          name_servers = Enum.map(v, & Regex.named_captures(@nameserver_regex, &1)["domain"])

          %{record | nameservers: name_servers}

        "registrar" ->
          %{record | registrar: v}

        "relevant dates" ->
          Enum.reduce(v, record, fn {k, v}, record ->
            case k do
              "registered on" ->
                %{record | created_at: parse_d(v) || record.created_at}

              "expiry date" ->
                %{record | expires_at: parse_d(v) || record.expires_at}

              "last updated" ->
                %{record | updated_at: parse_d(v) || record.updated_at}

              _ ->
                record
            end
          end)

        _ ->
          record
      end
    end)

    nameservers =
      record.nameservers
      |> Enum.map(&String.downcase/1)
      |> Enum.uniq()

    %{record | nameservers: nameservers}
  end

  defp parse_d(string) do
    case Timex.parse(string, "{D}-{Mshort}-{YYYY}") do
      {:ok, date} -> date
      {:error, _} -> nil
    end
  end

  defp parse_dt(string) do
    case NaiveDateTime.from_iso8601(string) do
      {:ok, datetime} -> datetime
      {:error, _} -> nil
    end
  end

  defp parse_contact(%Contact{} = contact, name, value) do
    key =
      case name do
        "name" -> :name
        "organization" -> :organization
        "street" -> :street
        "city" -> :city
        "state/province" -> :state
        "postal code" -> :zip
        "country" -> :country
        "phone" -> :phone
        "fax" -> :fax
        "email" -> :email
        _ -> nil
      end

    if key do
      %{contact | key => value}
    else
      contact
    end
  end
end

defimpl Inspect, for: Whois.Record do
  def inspect(%Whois.Record{} = record, opts) do
    record
    |> Map.put(:raw, "…")
    |> Map.delete(:__struct__)
    |> Inspect.Map.inspect("Whois.Record", opts)
  end
end
