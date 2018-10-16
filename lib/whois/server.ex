defmodule Whois.Server do
  defstruct [:host]

  @type t :: %__MODULE__{host: String.t()}

  @all File.read!(Application.app_dir(:whois, "priv/tld.csv"))
       |> String.trim()
       # bloody windows file endings
       |> String.replace("\r\n", "\n")
       |> String.split("\n")
       |> Enum.map(fn line ->
         [tld, host] = String.split(line, ",")
         {tld, %{__struct__: __MODULE__, host: host}}
       end)
       |> Map.new()

  @spec all :: map
  def all, do: @all

  @spec split_right(String.t(), String.t()) :: {String.t(), String.t()}
  defp split_right(s, pat) do
    pieces = String.split(s, pat)

    {last, rest} = List.pop_at(pieces, -1)

    {Enum.join(rest, pat), last}
  end

  @spec for(String.t()) :: {:ok, t} | :error
  def for(domain) do
    {_, tld} = split_right(domain, ".")
    Map.fetch(@all, tld)
  end
end
