variable "type" {
  description = "The type of the vector install, whether 'baseline' or 'comparision'"
  type        = string
}

variable "vector_image" {
  description = "The image of vector to use in this investigation"
  type        = string
}
